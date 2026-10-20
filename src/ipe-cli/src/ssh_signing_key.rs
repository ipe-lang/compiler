//! The SSH key `ipe package publish` signs the index commit with: where publish
//! finds it, and the opt-in `ipe login` step that generates one and registers it
//! on the GitHub account as a *signing* key.
//!
//! Lookup order: `IPE_PUBLISH_SIGNING_KEY` wins whenever it is set — an explicit
//! value that names no usable key file fails closed, it never falls back to the
//! stored key. Unset, publish uses the key `ipe login` stored at
//! `<config dir>/signing_key`, and only once its open handle proves it a regular
//! file private to the invoking user; an exposed or unusable stored key is
//! reported and never signed with.
//!
//! Setup is interactive and opt-in only. It generates a dedicated ed25519 key in
//! process (no `ssh-keygen` subprocess), stages both halves in the config dir
//! under fresh names (the private half created `0600`, exclusively, never through
//! a symlink) and proves the dir supports the hard links the final step makes,
//! registers the public half through `POST /user/ssh_signing_keys`
//! with a separate one-shot `write:ssh_signing_key` authorization, and only then
//! links the staged files into their final names. Any failure before that commit
//! point removes the staged files, so a key the account does not know is never
//! left where publish would pick it up.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::CliError;
use crate::login::KeyRegistrationToken;
use crate::proven_dir::EntryName;
use crate::secret_file::{DirRefusal, HOST_SECRET_STORE, OwnerDir, SecretFileError, SecretStore};

/// The environment variable naming the SSH signing key's private-key file.
pub const SIGNING_KEY_ENV: &str = "IPE_PUBLISH_SIGNING_KEY";

/// File name of the generated private key inside the ipe config dir.
const PRIVATE_KEY_FILE: &str = "signing_key";
/// File name of the generated public key inside the ipe config dir.
const PUBLIC_KEY_FILE: &str = "signing_key.pub";

/// The OpenSSH key-type name for ed25519.
const KEY_TYPE: &[u8] = b"ssh-ed25519";
/// The comment embedded in the generated key.
const KEY_COMMENT: &str = "ipe-publish";
/// The title the key is registered under on the GitHub account.
const KEY_TITLE: &str = "ipe package publish";

/// The GitHub REST endpoint that adds an SSH *signing* key (`/user/keys` adds
/// authentication keys, which GitHub never uses to mark a commit "Verified").
const SIGNING_KEYS_API: &str = "https://api.github.com/user/ssh_signing_keys";
/// Where the user reviews or deletes registered keys.
const SIGNING_KEYS_SETTINGS: &str = "https://github.com/settings/keys";
/// Where the user reviews or revokes the OAuth grants `ipe login` obtained.
const AUTHORIZED_APPS_SETTINGS: &str = "https://github.com/settings/applications";

/// Upper bound on the length of a GitHub error message echoed to the terminal.
const MAX_ECHOED_MESSAGE_CHARS: usize = 200;

/// Path to an SSH private-key file that publish hands to `git` for signing.
///
/// Holds only a path that named a regular file when it was parsed; the key bytes
/// never enter the process through this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyPath(PathBuf);

impl PrivateKeyPath {
    /// Parse an `IPE_PUBLISH_SIGNING_KEY` value: a non-blank UTF-8 path to an
    /// existing regular file (symlinks followed — the path is the user's choice).
    #[must_use]
    pub fn from_env_value(raw: &OsStr) -> Option<Self> {
        let trimmed = raw.to_str()?.trim();
        if trimmed.is_empty() {
            return None;
        }
        let path = PathBuf::from(trimmed);
        std::fs::metadata(&path)
            .is_ok_and(|m| m.is_file())
            .then_some(Self(path))
    }

    /// The private-key file's path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// The occupant of the stored key's name, as its open handle proved it.
///
/// The name is opened without following a final symlink and the handle's
/// metadata decides: only a regular file private to the invoking user is
/// `Proven`.
#[derive(Debug, PartialEq, Eq)]
enum StoredKey {
    /// A regular file private to the invoking user.
    Proven(PrivateKeyPath),
    /// A regular file another user can read, or that another user owns.
    Exposed(PathBuf),
    /// A symlink, directory, FIFO, or unreadable entry holds the name.
    Unusable(PathBuf),
    /// The config dir, or an ancestor, was refused before the key's name was looked at.
    DirRefused(DirRefusal),
    /// Nothing holds the name, or the host cannot prove a secret file private.
    Absent,
}

impl StoredKey {
    /// Probe `<config_dir>/signing_key` through `store`.
    ///
    /// A config dir that is a link, or that another user could write, holds
    /// no trusted key; it is `DirRefused` with the typed cause, and nothing
    /// under it is looked at.
    fn probe(store: SecretStore, config_dir: &Path) -> Self {
        let path = config_dir.join(PRIVATE_KEY_FILE);
        match crate::secret_file::open_existing(store, &path) {
            Ok(_) => Self::Proven(PrivateKeyPath(path)),
            Err(SecretFileError::Dir(refusal)) => Self::DirRefused(refusal),
            Err(SecretFileError::NotOwnerOnly(shown)) => Self::Exposed(shown),
            Err(SecretFileError::NotRegularFile(shown)) => Self::Unusable(shown),
            Err(SecretFileError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Self::Absent,
            Err(SecretFileError::Io(_)) => Self::Unusable(path),
            Err(SecretFileError::Unsupported) => Self::Absent,
        }
    }
}

/// Where the key publish will sign with comes from.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyLookup {
    /// `IPE_PUBLISH_SIGNING_KEY` names a usable key; it wins over a stored key.
    Env(PrivateKeyPath),
    /// `IPE_PUBLISH_SIGNING_KEY` is set but names no usable key file. Publish
    /// refuses rather than silently use a different (stored) key.
    EnvUnusable,
    /// The key `ipe login` generated and registered, proven private to the
    /// invoking user.
    Stored(PrivateKeyPath),
    /// The stored key is readable by, or owned by, another user; it is treated
    /// as exposed and never signed with.
    StoredExposed(PathBuf),
    /// Something other than a readable regular file holds the stored key's name.
    StoredUnusable(PathBuf),
    /// The config dir, or an ancestor, was refused, so no stored key is trusted.
    StoredDirRefused(DirRefusal),
    /// No key is configured.
    Missing,
}

impl KeyLookup {
    /// The key publish signs with, if any.
    #[must_use]
    pub fn usable(self) -> Option<PrivateKeyPath> {
        match self {
            Self::Env(path) | Self::Stored(path) => Some(path),
            Self::EnvUnusable
            | Self::StoredExposed(_)
            | Self::StoredUnusable(_)
            | Self::StoredDirRefused(_)
            | Self::Missing => None,
        }
    }
}

/// Resolve the signing key from the `IPE_PUBLISH_SIGNING_KEY` value and the ipe
/// config dir. A set, non-blank variable is authoritative; otherwise the stored
/// key is used.
#[must_use]
pub fn lookup(env_value: Option<&OsStr>, config_dir: Option<&Path>) -> KeyLookup {
    lookup_in(HOST_SECRET_STORE, env_value, config_dir)
}

/// [`lookup`], proving the stored key through `store`.
fn lookup_in(
    store: SecretStore,
    env_value: Option<&OsStr>,
    config_dir: Option<&Path>,
) -> KeyLookup {
    let explicit = env_value.filter(|v| !v.to_str().is_some_and(|s| s.trim().is_empty()));
    explicit.map_or_else(
        || {
            config_dir.map_or(KeyLookup::Missing, |dir| {
                match StoredKey::probe(store, dir) {
                    StoredKey::Proven(path) => KeyLookup::Stored(path),
                    StoredKey::Exposed(path) => KeyLookup::StoredExposed(path),
                    StoredKey::Unusable(path) => KeyLookup::StoredUnusable(path),
                    StoredKey::DirRefused(refusal) => KeyLookup::StoredDirRefused(refusal),
                    StoredKey::Absent => KeyLookup::Missing,
                }
            })
        },
        |raw| PrivateKeyPath::from_env_value(raw).map_or(KeyLookup::EnvUnusable, KeyLookup::Env),
    )
}

/// The signing key publish uses in this process's environment.
#[must_use]
pub fn configured() -> Option<PrivateKeyPath> {
    lookup(
        ipe_env::var_os(SIGNING_KEY_ENV).as_deref(),
        crate::login::config_dir().as_deref(),
    )
    .usable()
}

/// One line for `ipe login --status` naming the key publish would sign with.
pub(crate) fn status_line(
    env_value: Option<&OsStr>,
    config_dir: Option<&Path>,
) -> crate::text::Message {
    match lookup(env_value, config_dir) {
        KeyLookup::Env(path) => {
            crate::text::signing_key_status_env(&shown_path(path.as_path()), &SIGNING_KEY_ENV)
        }
        KeyLookup::EnvUnusable => crate::text::signing_key_status_env_unusable(&SIGNING_KEY_ENV),
        KeyLookup::Stored(path) => {
            crate::text::signing_key_status_stored(&shown_path(path.as_path()))
        }
        KeyLookup::StoredExposed(path) => crate::text::signing_key_status_stored_exposed(
            &shown_path(&path),
            &SIGNING_KEYS_SETTINGS,
        ),
        KeyLookup::StoredUnusable(path) => {
            crate::text::signing_key_status_stored_unusable(&shown_path(&path))
        }
        KeyLookup::StoredDirRefused(DirRefusal::Symlinked(dir)) => {
            crate::text::signing_key_status_symlinked_dir(&shown_path(&dir))
        }
        KeyLookup::StoredDirRefused(DirRefusal::Untrusted(dir)) => {
            crate::text::signing_key_status_dir_untrusted(&shown_path(&dir), &SIGNING_KEYS_SETTINGS)
        }
        KeyLookup::Missing => crate::text::msg::signing_key_status_none(),
    }
}

/// A path as a terminal-safe message value.
fn shown_path(path: &Path) -> crate::style::TerminalSafe {
    crate::style::TerminalSafe::sanitize(&path.display().to_string())
}

/// An I/O error's detail as a terminal-safe message value.
fn shown_io(source: &std::io::Error) -> crate::style::TerminalSafe {
    crate::style::TerminalSafe::sanitize(&source.to_string())
}

/// An OpenSSH public-key line (`ssh-ed25519 <base64> <comment>`), produced only
/// by [`GeneratedKeyPair`].
pub(crate) struct SshPublicKey(String);

impl SshPublicKey {
    /// The public-key line, as GitHub's `key` field expects it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A freshly generated ed25519 keypair in OpenSSH encoding. The private half is
/// wiped from memory on drop.
struct GeneratedKeyPair {
    private_pem: Zeroizing<String>,
    public: SshPublicKey,
}

impl GeneratedKeyPair {
    /// Generate a keypair from the OS CSPRNG. `None` when the CSPRNG fails.
    fn generate() -> Option<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).ok()?;
        let mut check = [0u8; 4];
        getrandom::fill(&mut check).ok()?;
        Self::from_seed(&seed, u32::from_be_bytes(check))
    }

    /// Encode the keypair for `seed` in the unencrypted `openssh-key-v1` format.
    /// `check` is the format's integrity word, written twice in the private
    /// section.
    fn from_seed(seed: &[u8; 32], check: u32) -> Option<Self> {
        let public_key = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();

        let mut public_blob = Vec::with_capacity(51);
        put_string(&mut public_blob, KEY_TYPE)?;
        put_string(&mut public_blob, &public_key)?;

        // The OpenSSH ed25519 private scalar field is `seed || public key`.
        let mut secret = Zeroizing::new(Vec::<u8>::with_capacity(64));
        secret.extend_from_slice(seed);
        secret.extend_from_slice(&public_key);

        let mut private_section = Zeroizing::new(Vec::<u8>::with_capacity(160));
        private_section.extend_from_slice(&check.to_be_bytes());
        private_section.extend_from_slice(&check.to_be_bytes());
        put_string(&mut private_section, KEY_TYPE)?;
        put_string(&mut private_section, &public_key)?;
        put_string(&mut private_section, &secret)?;
        put_string(&mut private_section, KEY_COMMENT.as_bytes())?;
        // Pad to the cipher block size (8 for `none`) with 1, 2, 3, …
        let mut pad: u8 = 1;
        while !private_section.len().is_multiple_of(8) {
            private_section.push(pad);
            pad = pad.wrapping_add(1);
        }

        let mut body = Zeroizing::new(Vec::<u8>::with_capacity(256));
        body.extend_from_slice(b"openssh-key-v1\0");
        put_string(&mut body, b"none")?; // cipher
        put_string(&mut body, b"none")?; // kdf
        put_string(&mut body, b"")?; // kdf options
        body.extend_from_slice(&1u32.to_be_bytes()); // key count
        put_string(&mut body, &public_blob)?;
        put_string(&mut body, &private_section)?;

        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*body));
        let mut private_pem = Zeroizing::new(String::with_capacity(encoded.len() + 80));
        private_pem.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for line in encoded.as_bytes().chunks(70) {
            private_pem.push_str(std::str::from_utf8(line).ok()?);
            private_pem.push('\n');
        }
        private_pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");

        let public = SshPublicKey(format!(
            "ssh-ed25519 {} {KEY_COMMENT}",
            base64::engine::general_purpose::STANDARD.encode(&public_blob)
        ));
        Some(Self {
            private_pem,
            public,
        })
    }
}

/// Append an SSH wire-format `string` (big-endian `u32` length, then bytes).
/// `None` only for a field longer than `u32::MAX`, which no key field is.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

/// Why registering the public key on GitHub failed.
#[derive(Debug)]
pub(crate) enum RegistrationError {
    /// The `write:ssh_signing_key` device-flow authorization did not complete.
    Authorization(String),
    /// GitHub answered with a status other than `201 Created`.
    Refused { status: u16, message: String },
    /// The request never got an HTTP answer.
    Transport(String),
}

impl RegistrationError {
    /// The user-facing text of this failure.
    fn message(&self) -> crate::text::Message {
        use crate::style::TerminalSafe;
        match self {
            Self::Authorization(reason) => {
                crate::text::msg::signing_key_authorization_failed(&TerminalSafe::sanitize(reason))
            }
            Self::Refused { status, message } => {
                crate::text::msg::signing_key_refused(status, &TerminalSafe::sanitize(message))
            }
            Self::Transport(reason) => {
                crate::text::msg::signing_key_unreachable(&TerminalSafe::sanitize(reason))
            }
        }
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// Registers a public key as a signing key on the user's GitHub account. The
/// seam the tests fake so no network is touched.
pub(crate) trait SigningKeyRegistrar {
    /// Register `public_key` under `title`. `Ok` only when GitHub confirmed the
    /// key was created.
    fn register(&mut self, public_key: &SshPublicKey, title: &str)
    -> Result<(), RegistrationError>;
}

/// Asks the user a yes/no question; the default answer is no.
pub(crate) trait Consent {
    /// `true` only on an explicit yes.
    fn confirm(&mut self, question: &str) -> bool;
}

/// What the setup step did.
#[derive(Debug, PartialEq, Eq)]
enum SetupOutcome {
    /// A usable key is already configured; nothing was generated.
    AlreadyConfigured(PrivateKeyPath),
    /// `IPE_PUBLISH_SIGNING_KEY` is set but unusable; nothing was generated,
    /// because a stored key would be shadowed by the variable anyway.
    EnvUnusable,
    /// The user declined; nothing was generated.
    Declined,
    /// A key was generated, registered on GitHub, and stored at this path.
    Registered(PrivateKeyPath),
}

impl SetupOutcome {
    fn message(&self) -> crate::text::Message {
        match self {
            Self::AlreadyConfigured(path) => {
                crate::text::signing_key_already_configured(&shown_path(path.as_path()))
            }
            Self::EnvUnusable => crate::text::signing_key_env_unusable(&SIGNING_KEY_ENV),
            Self::Declined => crate::text::signing_key_declined(&SIGNING_KEY_ENV),
            Self::Registered(path) => crate::text::signing_key_registered(
                &shown_path(path.as_path()),
                &SIGNING_KEYS_SETTINGS,
            ),
        }
    }
}

/// Why the setup step failed. Every variant leaves no staged key behind.
#[derive(Debug)]
enum SetupError {
    /// Neither `XDG_CONFIG_HOME` nor `HOME` is set.
    NoConfigDir,
    /// This host cannot keep the private key in a file readable by its owner alone.
    StoreUnsupported,
    /// Something already occupies a key file name.
    Occupied(PathBuf),
    /// A key file or the config dir is not private to the invoking user.
    NotOwnerOnly(PathBuf),
    /// The config dir is a symbolic link.
    SymlinkedDir(PathBuf),
    /// The stored key is already registered on GitHub but is not private to the
    /// invoking user; it must be revoked on GitHub, never silently replaced.
    StoredKeyExposed(PathBuf),
    /// The config dir cannot hold hard links, which storing the key relies on.
    LinkUnsupported {
        dir: PathBuf,
        source: std::io::Error,
    },
    /// The OS CSPRNG failed.
    KeyGeneration,
    /// A filesystem step before registration failed.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Registration failed; the local key was removed.
    Registration(RegistrationError),
    /// The key IS registered on GitHub but could not be moved into place locally.
    Commit {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl SetupError {
    /// The user-facing text of this failure.
    fn message(&self) -> crate::text::Message {
        use crate::text::msg;
        match self {
            Self::NoConfigDir => msg::signing_key_no_config_dir(),
            Self::StoreUnsupported => msg::signing_key_store_unsupported(&SIGNING_KEY_ENV),
            Self::Occupied(path) => msg::signing_key_occupied(&shown_path(path)),
            Self::NotOwnerOnly(path) => {
                msg::signing_key_not_owner_only(&shown_path(path), &SIGNING_KEY_ENV)
            }
            Self::SymlinkedDir(path) => msg::signing_key_symlinked_dir(&shown_path(path)),
            Self::StoredKeyExposed(path) => {
                msg::signing_key_stored_exposed(&shown_path(path), &SIGNING_KEYS_SETTINGS)
            }
            Self::LinkUnsupported { dir, source } => msg::signing_key_link_unsupported(
                &shown_path(dir),
                &shown_io(source),
                &SIGNING_KEY_ENV,
            ),
            Self::KeyGeneration => msg::signing_key_generation_failed(),
            Self::Io { path, source } => {
                msg::signing_key_write_failed(&shown_path(path), &shown_io(source))
            }
            Self::Registration(e) => msg::signing_key_registration_failed(&e.message()),
            Self::Commit { path, source } => msg::signing_key_commit_failed(
                &shown_path(path),
                &shown_io(source),
                &KEY_TITLE,
                &SIGNING_KEYS_SETTINGS,
            ),
        }
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// The stored keypair's final names, inside the held config dir.
struct KeyFiles {
    dir: OwnerDir,
    private: EntryName,
    public: EntryName,
    link_probe: EntryName,
}

/// File name, beneath its temporary suffix, of the hard-link probe.
const LINK_PROBE_FILE: &str = "signing_key.link-probe";

impl KeyFiles {
    /// The keypair's names inside the held config dir `dir`.
    fn in_dir(dir: OwnerDir) -> Result<Self, SetupError> {
        let entry = |text: &str| {
            EntryName::new(OsStr::new(text)).ok_or_else(|| SetupError::Io {
                path: dir.path().join(text),
                source: std::io::ErrorKind::InvalidInput.into(),
            })
        };
        let private = entry(PRIVATE_KEY_FILE)?;
        let public = entry(PUBLIC_KEY_FILE)?;
        let link_probe = entry(LINK_PROBE_FILE)?;
        Ok(Self {
            dir,
            private,
            public,
            link_probe,
        })
    }

    /// The private key's final path.
    fn private_path(&self) -> PathBuf {
        self.dir.path_of(&self.private)
    }

    /// Refuse when anything (file, symlink, directory) already holds either name.
    fn ensure_free(&self) -> Result<(), SetupError> {
        for name in [&self.private, &self.public] {
            match self.dir.is_vacant(name) {
                Ok(true) => {}
                Ok(false) => return Err(SetupError::Occupied(self.dir.path_of(name))),
                Err(source) => {
                    return Err(SetupError::Io {
                        path: self.dir.path_of(name),
                        source,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Both halves written under fresh temporary names in the held config dir.
///
/// Dropping it removes the temporary names, so any early return before
/// [`Self::commit`] leaves nothing, and after the commit only the final names
/// remain.
struct StagedKeyPair<'f> {
    files: &'f KeyFiles,
    private_tmp: EntryName,
    public_tmp: EntryName,
}

impl<'f> StagedKeyPair<'f> {
    /// Write `pair` beside `files` under unique temporary names.
    ///
    /// The private half is created owner-only before any byte lands in it;
    /// the public half is created `0644`. Both are created through the held
    /// config dir, never by path.
    ///
    /// Also proves the directory supports the hard links [`Self::commit`] makes,
    /// so a filesystem without them fails here — before anything is registered
    /// on GitHub — rather than after, which would orphan a registered key.
    fn write(files: &'f KeyFiles, pair: &GeneratedKeyPair) -> Result<Self, SetupError> {
        let dir = &files.dir;
        let suffix =
            crate::secret_file::TempSuffix::fresh().map_err(|_| SetupError::KeyGeneration)?;
        let temp_name = |name: &EntryName| {
            suffix.name_for(name).map_err(|source| SetupError::Io {
                path: dir.path_of(name),
                source,
            })
        };
        let public_tmp = temp_name(&files.public)?;
        let probe = temp_name(&files.link_probe)?;
        let (private, private_tmp) = dir
            .create_temp_for(&files.private, &suffix)
            .map_err(|e| secret_file_error(e, &dir.path_of(&files.private)))?;
        let staged = Self {
            files,
            private_tmp,
            public_tmp,
        };
        fill_new_file(
            dir,
            &staged.private_tmp,
            private,
            pair.private_pem.as_bytes(),
        )?;
        let public = dir
            .create_public(&staged.public_tmp)
            .map_err(|source| SetupError::Io {
                path: dir.path_of(&staged.public_tmp),
                source,
            })?;
        fill_new_file(
            dir,
            &staged.public_tmp,
            public,
            format!("{}\n", pair.public.as_str()).as_bytes(),
        )?;
        probe_hard_link(dir, &staged.public_tmp, &probe)?;
        Ok(staged)
    }

    /// Link both halves into their final names.
    ///
    /// The private key is linked last: it is the name publish looks for, so
    /// it appears only once the public half is in place. A hard link refuses
    /// an existing name, so a file that appeared meanwhile is never
    /// overwritten.
    fn commit(self) -> Result<PrivateKeyPath, SetupError> {
        let files = self.files;
        let dir = &files.dir;
        dir.hard_link(&self.public_tmp, &files.public)
            .map_err(|source| SetupError::Commit {
                path: dir.path_of(&files.public),
                source,
            })?;
        if let Err(source) = dir.hard_link(&self.private_tmp, &files.private) {
            let _ = dir.remove(&files.public);
            return Err(SetupError::Commit {
                path: files.private_path(),
                source,
            });
        }
        Ok(PrivateKeyPath(files.private_path()))
    }
}

impl Drop for StagedKeyPair<'_> {
    fn drop(&mut self) {
        let _ = self.files.dir.remove(&self.private_tmp);
        let _ = self.files.dir.remove(&self.public_tmp);
    }
}

/// Hard-link `source` in `dir` to the unused name `probe`, then remove `probe`.
fn probe_hard_link(
    dir: &OwnerDir,
    source: &EntryName,
    probe: &EntryName,
) -> Result<(), SetupError> {
    dir.hard_link(source, probe)
        .map_err(|source| SetupError::LinkUnsupported {
            dir: dir.path().to_path_buf(),
            source,
        })?;
    dir.remove(probe).map_err(|source| SetupError::Io {
        path: dir.path_of(probe),
        source,
    })
}

/// The setup failure for a secret-file step on `path` that failed with `error`.
fn secret_file_error(error: SecretFileError, path: &Path) -> SetupError {
    match error {
        SecretFileError::Unsupported => SetupError::StoreUnsupported,
        SecretFileError::Io(source) => SetupError::Io {
            path: path.to_path_buf(),
            source,
        },
        SecretFileError::NotOwnerOnly(shown)
        | SecretFileError::Dir(DirRefusal::Untrusted(shown)) => SetupError::NotOwnerOnly(shown),
        SecretFileError::Dir(DirRefusal::Symlinked(dir)) => SetupError::SymlinkedDir(dir),
        SecretFileError::NotRegularFile(shown) => SetupError::Occupied(shown),
    }
}

/// Write and sync `contents` into the freshly created `file`, the entry `name` of `dir`.
///
/// A partially written file is removed.
fn fill_new_file(
    dir: &OwnerDir,
    name: &EntryName,
    mut file: File,
    contents: &[u8],
) -> Result<(), SetupError> {
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    written.map_err(|source| {
        let _ = dir.remove(name);
        SetupError::Io {
            path: dir.path_of(name),
            source,
        }
    })
}

/// Hold the config dir through `store`, creating it owner-only and refusing one another user can write.
fn create_config_dir(store: SecretStore, dir: &Path) -> Result<OwnerDir, SetupError> {
    crate::secret_file::create_owner_dir(store, dir).map_err(|e| secret_file_error(e, dir))
}

/// The consent question: what will be generated, where it is stored, and the
/// extra scope the one-shot registration authorization asks for.
fn consent_question(private_key: &Path) -> crate::text::Message {
    crate::text::signing_key_consent_question(
        &shown_path(private_key),
        &crate::login::SIGNING_KEY_SCOPE,
        &AUTHORIZED_APPS_SETTINGS,
    )
}

/// The setup step: skip when a key is configured, otherwise ask, generate,
/// stage, register, and commit — removing the staged key on any failure.
///
/// An exposed or unusable stored key is refused before the question is asked,
/// and the config dir is proven owner-only before any key is generated.
fn set_up<C: Consent, R: SigningKeyRegistrar>(
    store: SecretStore,
    env_value: Option<&OsStr>,
    config_dir: Option<&Path>,
    consent: &mut C,
    registrar: &mut R,
) -> Result<SetupOutcome, SetupError> {
    let dir = match lookup_in(store, env_value, config_dir) {
        KeyLookup::Env(path) | KeyLookup::Stored(path) => {
            return Ok(SetupOutcome::AlreadyConfigured(path));
        }
        KeyLookup::EnvUnusable => return Ok(SetupOutcome::EnvUnusable),
        KeyLookup::StoredExposed(path) => return Err(SetupError::StoredKeyExposed(path)),
        KeyLookup::StoredUnusable(path) => return Err(SetupError::Occupied(path)),
        KeyLookup::StoredDirRefused(DirRefusal::Untrusted(dir)) => {
            return Err(SetupError::NotOwnerOnly(dir));
        }
        KeyLookup::StoredDirRefused(DirRefusal::Symlinked(dir)) => {
            return Err(SetupError::SymlinkedDir(dir));
        }
        KeyLookup::Missing => config_dir.ok_or(SetupError::NoConfigDir)?,
    };
    let files = KeyFiles::in_dir(create_config_dir(store, dir)?)?;
    files.ensure_free()?;
    if !consent.confirm(&consent_question(&files.private_path())) {
        return Ok(SetupOutcome::Declined);
    }
    let pair = GeneratedKeyPair::generate().ok_or(SetupError::KeyGeneration)?;
    let staged = StagedKeyPair::write(&files, &pair)?;
    registrar
        .register(&pair.public, KEY_TITLE)
        .map_err(SetupError::Registration)?;
    staged.commit().map(SetupOutcome::Registered)
}

/// Reads the answer from the terminal.
struct TerminalConsent;

impl Consent for TerminalConsent {
    fn confirm(&mut self, question: &str) -> bool {
        crate::screen::prompt(&format!("\n{question} [y/N] "));
        crate::read_yes_no_default(false)
    }
}

/// Registers through the GitHub REST API after a one-shot device-flow grant.
struct GithubRegistrar;

impl SigningKeyRegistrar for GithubRegistrar {
    fn register(
        &mut self,
        public_key: &SshPublicKey,
        title: &str,
    ) -> Result<(), RegistrationError> {
        let token = crate::login::authorize_signing_key_registration()
            .map_err(|e| RegistrationError::Authorization(e.to_string()))?;
        post_signing_key(&token, public_key, title)
    }
}

/// `POST /user/ssh_signing_keys`. Only `201 Created` counts as registered. The
/// token travels in-process in the `Authorization` header — never on an argv —
/// and is dropped when this returns.
fn post_signing_key(
    token: &KeyRegistrationToken,
    public_key: &SshPublicKey,
    title: &str,
) -> Result<(), RegistrationError> {
    let body = serde_json::json!({ "title": title, "key": public_key.as_str() }).to_string();
    let authorization = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let result = crate::net::agent(Duration::from_secs(30))
        .post(SIGNING_KEYS_API)
        .header("User-Agent", "ipe-cli")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Content-Type", "application/json")
        .header("Authorization", authorization.as_str())
        .send(body.as_str());
    registration_outcome(result)
}

/// The registration verdict of one `POST` answer: only `201 Created` counts.
fn registration_outcome(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<(), RegistrationError> {
    match result {
        Ok(response) if response.status().as_u16() == 201 => Ok(()),
        Ok(response) => Err(RegistrationError::Refused {
            status: response.status().as_u16(),
            message: github_message(response),
        }),
        Err(ureq::Error::StatusCode(status)) => Err(RegistrationError::Refused {
            status,
            message: echoed_message(""),
        }),
        Err(transport) => Err(RegistrationError::Transport(transport.to_string())),
    }
}

/// GitHub's `message` field as one capped terminal line, so a hostile
/// response cannot drive the terminal; see [`echoed_message`].
///
/// The body is read through [`crate::remote_ingest::read_capped`] at
/// [`crate::remote_ingest::JSON_RESPONSE_MAX_BYTES`]; an over-budget body
/// carries no message.
fn github_message(response: ureq::http::Response<ureq::Body>) -> String {
    let body = response.into_body();
    let message = crate::remote_ingest::read_capped(
        body.into_reader(),
        crate::remote_ingest::JSON_RESPONSE_MAX_BYTES,
        crate::remote_ingest::IngestSource::GithubApi,
    )
    .ok()
    .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
    .and_then(|json| {
        json.get("message")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
    .unwrap_or_default();
    echoed_message(&message)
}

/// An untrusted response message parsed into one [`crate::style::TerminalLine`]
/// (every escape sequence dropped whole, no control or denied format
/// character) and capped at [`MAX_ECHOED_MESSAGE_CHARS`] characters.
fn echoed_message(message: &str) -> String {
    let cleaned: String = crate::style::TerminalLine::sanitize(message)
        .as_str()
        .chars()
        .take(MAX_ECHOED_MESSAGE_CHARS)
        .collect();
    if cleaned.is_empty() {
        "no message".to_owned()
    } else {
        cleaned
    }
}

fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Run the setup against the real terminal and GitHub, printing the outcome.
fn run_interactive(env_value: Option<&OsStr>, config_dir: Option<&Path>) -> Result<(), CliError> {
    let outcome = set_up(
        HOST_SECRET_STORE,
        env_value,
        config_dir,
        &mut TerminalConsent,
        &mut GithubRegistrar,
    )
    .map_err(|e| crate::login::login_error(&e.message()))?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &outcome.message())
        .emit();
    Ok(())
}

/// The line `offer_after_login` prints without a terminal, if any: `Missing`
/// gets the generic no-terminal hint; an exposed or unusable stored key gets
/// its status line, so the reason it will not be used is spelled out even
/// without a prompt; a usable key (env or stored) prints nothing.
fn no_terminal_hint(
    env_value: Option<&OsStr>,
    config_dir: Option<&Path>,
) -> Option<crate::text::Message> {
    match lookup(env_value, config_dir) {
        KeyLookup::Missing => Some(crate::text::msg::signing_key_hint_no_terminal()),
        KeyLookup::StoredExposed(_)
        | KeyLookup::StoredUnusable(_)
        | KeyLookup::StoredDirRefused(_) => Some(status_line(env_value, config_dir)),
        KeyLookup::Env(_) | KeyLookup::EnvUnusable | KeyLookup::Stored(_) => None,
    }
}

/// After `ipe login` stored a token: offer signing-key setup when none is
/// configured. Without a terminal nothing is asked — only a hint is printed.
///
/// # Errors
/// [`CliError::Resolve`] when the user opted in and setup failed; no partial key
/// is left behind.
pub(crate) fn offer_after_login() -> Result<(), CliError> {
    let env_value = ipe_env::var_os(SIGNING_KEY_ENV);
    let config_dir = crate::login::config_dir();
    if is_interactive() {
        return run_interactive(env_value.as_deref(), config_dir.as_deref());
    }
    if let Some(hint) = no_terminal_hint(env_value.as_deref(), config_dir.as_deref()) {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(crate::screen::Tone::Aux, &hint)
            .emit();
    }
    Ok(())
}

/// `ipe login --signing-key`: the setup step on its own.
///
/// # Errors
/// [`CliError::Resolve`] without an interactive terminal, or when setup failed;
/// no partial key is left behind.
pub(crate) fn run_setup_command() -> Result<(), CliError> {
    if !is_interactive() {
        return Err(crate::login::login_error(
            &crate::text::msg::signing_key_needs_terminal(),
        ));
    }
    run_interactive(
        ipe_env::var_os(SIGNING_KEY_ENV).as_deref(),
        crate::login::config_dir().as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hostile response message loses each escape sequence whole, not just
    /// its `ESC`, and every bidi or zero-width character, before it is echoed.
    #[test]
    fn echoed_message_drops_escape_sequences_whole_and_format_chars() {
        let hostile = "Bad\u{1b}[31m key\u{1b}]8;;https://evil.example\u{7}\u{202e}here\u{200b}\n!";
        assert_eq!(echoed_message(hostile), "Bad keyhere!");
        assert_eq!(echoed_message("\u{1b}[2J\u{202e}"), "no message");
        let long = "x".repeat(MAX_ECHOED_MESSAGE_CHARS + 5);
        assert_eq!(
            echoed_message(&long).chars().count(),
            MAX_ECHOED_MESSAGE_CHARS
        );
    }

    /// RFC 8032 §7.1 test 1 secret seed.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn test_dir(tag: &str) -> PathBuf {
        let base = ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp dir");
        let dir = base.join(format!(
            "ipe-signing-key-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn dir_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    struct Answer {
        yes: bool,
        asked: usize,
    }

    impl Consent for Answer {
        fn confirm(&mut self, _question: &str) -> bool {
            self.asked += 1;
            self.yes
        }
    }

    struct FakeRegistrar {
        refuse: bool,
        /// A final key-file name another writer claims while registration runs.
        plant_on_register: Option<&'static str>,
        calls: usize,
        seen_key: Option<String>,
        staged_private_mode: Option<u32>,
        dir: PathBuf,
    }

    impl FakeRegistrar {
        fn new(dir: &Path, refuse: bool) -> Self {
            Self {
                refuse,
                plant_on_register: None,
                calls: 0,
                seen_key: None,
                staged_private_mode: None,
                dir: dir.to_path_buf(),
            }
        }
    }

    impl SigningKeyRegistrar for FakeRegistrar {
        fn register(
            &mut self,
            public_key: &SshPublicKey,
            _title: &str,
        ) -> Result<(), RegistrationError> {
            self.calls += 1;
            self.seen_key = Some(public_key.as_str().to_owned());
            if let Some(name) = self.plant_on_register {
                std::fs::write(self.dir.join(name), b"planted").expect("plant");
            }
            // Observe the staged private key's mode at the moment of registration.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                self.staged_private_mode = std::fs::read_dir(&self.dir)
                    .expect("readdir")
                    .filter_map(Result::ok)
                    .find(|e| {
                        let name = e.file_name().to_string_lossy().into_owned();
                        name.starts_with(".signing_key.")
                            && !name.starts_with(".signing_key.pub.")
                            && Path::new(&name).extension() == Some(OsStr::new("tmp"))
                    })
                    .map(|e| e.metadata().expect("metadata").permissions().mode() & 0o777);
            }
            if self.refuse {
                Err(RegistrationError::Refused {
                    status: 403,
                    message: "Resource not accessible by integration".to_owned(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn encodes_the_rfc8032_key_in_openssh_format() {
        let pair = GeneratedKeyPair::from_seed(&RFC8032_SEED, 0x0102_0304).expect("encodes");
        assert_eq!(
            pair.public.as_str(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea ipe-publish"
        );
        assert_eq!(
            pair.private_pem.as_str(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
             QyNTUxOQAAACDXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAJABAgMEAQID\n\
             BAAAAAtzc2gtZWQyNTUxOQAAACDXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg\n\
             AAAECdYbGd7/1aYLqESvSS7CzEREnFaXsyaRlwO6wDHK5/YNdamAGCsQq31Uv+08lkBzoO\n\
             4XLz2qYjJa8CGmj3B1EaAAAAC2lwZS1wdWJsaXNoAQI=\n\
             -----END OPENSSH PRIVATE KEY-----\n"
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = GeneratedKeyPair::generate().expect("csprng");
        let b = GeneratedKeyPair::generate().expect("csprng");
        assert_ne!(a.public.as_str(), b.public.as_str());
        assert!(
            a.public
                .as_str()
                .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
        );
    }

    #[test]
    fn declined_prompt_generates_nothing() {
        let dir = test_dir("declined");
        let mut consent = Answer {
            yes: false,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let outcome = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        )
        .expect("declined");
        assert_eq!(outcome, SetupOutcome::Declined);
        assert_eq!(consent.asked, 1);
        assert_eq!(registrar.calls, 0, "nothing is registered after a decline");
        assert!(
            dir_entries(&dir).is_empty(),
            "no file is written after a decline"
        );
        assert_eq!(lookup(None, Some(dir.as_path())), KeyLookup::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn api_error_rolls_back_the_local_key() {
        let dir = test_dir("rollback");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, true);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(matches!(
            result,
            Err(SetupError::Registration(RegistrationError::Refused {
                status: 403,
                ..
            }))
        ));
        assert_eq!(registrar.calls, 1);
        assert!(
            dir_entries(&dir).is_empty(),
            "a failed registration leaves no key file: {:?}",
            dir_entries(&dir)
        );
        assert_eq!(
            lookup(None, Some(dir.as_path())),
            KeyLookup::Missing,
            "publish finds no key after a failed registration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registered_key_is_stored_owner_only_and_found_by_publish() {
        let dir = test_dir("registered");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let outcome = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        )
        .expect("registered");
        let private = dir.join(PRIVATE_KEY_FILE);
        assert_eq!(
            outcome,
            SetupOutcome::Registered(PrivateKeyPath(private.clone()))
        );
        assert_eq!(
            dir_entries(&dir),
            vec![PRIVATE_KEY_FILE.to_owned(), PUBLIC_KEY_FILE.to_owned()],
            "only the final names remain"
        );
        let stored_pub = std::fs::read_to_string(dir.join(PUBLIC_KEY_FILE)).expect("pub");
        assert_eq!(
            Some(stored_pub.trim_end().to_owned()),
            registrar.seen_key,
            "the stored public key is the one registered"
        );
        let pem = std::fs::read_to_string(&private).expect("private");
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&private)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "private key must be 0600, got {mode:04o}");
            assert_eq!(
                registrar.staged_private_mode,
                Some(0o600),
                "the staged private key is 0600 from creation"
            );
        }
        assert_eq!(
            lookup(None, Some(dir.as_path())),
            KeyLookup::Stored(PrivateKeyPath(private))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Plant `contents` at `path` with permission bits `mode`.
    #[cfg(unix)]
    fn plant_with_mode(path: &Path, contents: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, contents).expect("plant");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[cfg(unix)]
    #[test]
    fn a_configured_key_is_not_replaced() {
        let dir = test_dir("configured");
        plant_with_mode(&dir.join(PRIVATE_KEY_FILE), b"existing", 0o600);
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let outcome = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        )
        .expect("skip");
        assert!(matches!(outcome, SetupOutcome::AlreadyConfigured(_)));
        assert_eq!(consent.asked, 0, "no prompt when a key is configured");
        assert_eq!(registrar.calls, 0);
        assert_eq!(
            std::fs::read(dir.join(PRIVATE_KEY_FILE)).expect("read"),
            b"existing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_key_name_is_refused_before_registering() {
        let dir = test_dir("symlink");
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"not ours").expect("plant target");
        std::os::unix::fs::symlink(&target, dir.join(PRIVATE_KEY_FILE)).expect("plant symlink");
        assert_eq!(
            lookup(None, Some(dir.as_path())),
            KeyLookup::StoredUnusable(dir.join(PRIVATE_KEY_FILE)),
            "a symlinked stored key is reported unusable, never followed"
        );
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(matches!(result, Err(SetupError::Occupied(_))));
        assert_eq!(consent.asked, 0);
        assert_eq!(
            registrar.calls, 0,
            "nothing registered when a name is occupied"
        );
        assert_eq!(std::fs::read(&target).expect("read"), b"not ours");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A final name claimed between staging and commit fails the commit without
    /// overwriting the claimant and without leaving any half of our key behind.
    fn assert_commit_refused_when_planted(tag: &str, planted: &'static str) {
        let dir = test_dir(tag);
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        registrar.plant_on_register = Some(planted);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert_eq!(registrar.calls, 1);
        assert!(
            matches!(&result, Err(SetupError::Commit { path, .. }) if *path == dir.join(planted)),
            "expected a commit refusal naming {planted}, got {result:?}"
        );
        assert_eq!(
            dir_entries(&dir),
            vec![planted.to_owned()],
            "only the planted file remains: no staged, probe, or final file of ours"
        );
        assert_eq!(
            std::fs::read(dir.join(planted)).expect("read planted"),
            b"planted",
            "the planted file is never overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_private_key_name_claimed_before_commit_leaves_none_of_our_files() {
        assert_commit_refused_when_planted("commit-private", PRIVATE_KEY_FILE);
    }

    #[test]
    fn a_public_key_name_claimed_before_commit_leaves_none_of_our_files() {
        assert_commit_refused_when_planted("commit-public", PUBLIC_KEY_FILE);
    }

    #[test]
    fn a_lone_public_key_file_is_refused_before_registering() {
        let dir = test_dir("lone-pub");
        std::fs::write(dir.join(PUBLIC_KEY_FILE), b"someone else's").expect("plant pub");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(&result, Err(SetupError::Occupied(path)) if *path == dir.join(PUBLIC_KEY_FILE)),
            "expected Occupied(signing_key.pub), got {result:?}"
        );
        assert_eq!(consent.asked, 0);
        assert_eq!(registrar.calls, 0);
        assert_eq!(dir_entries(&dir), vec![PUBLIC_KEY_FILE.to_owned()]);
        assert_eq!(
            std::fs::read(dir.join(PUBLIC_KEY_FILE)).expect("read"),
            b"someone else's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_config_dir_is_refused_before_asking() {
        let dir = test_dir("no-config-dir");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(HOST_SECRET_STORE, None, None, &mut consent, &mut registrar);
        assert!(
            matches!(result, Err(SetupError::NoConfigDir)),
            "expected NoConfigDir, got {result:?}"
        );
        assert_eq!(consent.asked, 0);
        assert_eq!(registrar.calls, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The entry name `text`, which the test knows to be one plain component.
    #[cfg(unix)]
    fn entry(text: &str) -> EntryName {
        EntryName::new(OsStr::new(text)).expect("a plain component")
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_hard_link_probe_is_link_unsupported_and_touches_nothing() {
        let dir = test_dir("probe");
        let held = create_config_dir(SecretStore::OwnerOnlyFile, &dir).expect("hold test dir");
        std::fs::write(dir.join("source"), b"source").expect("plant source");
        let occupied = dir.join("occupied");
        std::fs::write(&occupied, b"occupied").expect("plant occupied");
        let result = probe_hard_link(&held, &entry("source"), &entry("occupied"));
        assert!(
            matches!(&result, Err(SetupError::LinkUnsupported { dir: d, .. }) if *d == dir),
            "expected LinkUnsupported, got {result:?}"
        );
        assert_eq!(std::fs::read(&occupied).expect("read"), b"occupied");

        probe_hard_link(&held, &entry("source"), &entry("probe"))
            .expect("links on a hard-link filesystem");
        assert_eq!(
            dir_entries(&dir),
            vec!["occupied".to_owned(), "source".to_owned()],
            "a successful probe leaves no probe file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_consent_question_names_where_to_revoke_the_grant() {
        let question = consent_question(Path::new("/cfg/ipe/signing_key"));
        assert!(question.contains("write:ssh_signing_key"));
        assert!(question.contains(AUTHORIZED_APPS_SETTINGS));
    }

    #[cfg(unix)]
    #[test]
    fn env_override_wins_over_the_stored_key() {
        let dir = test_dir("env-wins");
        let stored = dir.join(PRIVATE_KEY_FILE);
        plant_with_mode(&stored, b"stored", 0o600);
        let explicit = dir.join("explicit_key");
        std::fs::write(&explicit, b"explicit").expect("plant explicit");

        assert_eq!(
            lookup(Some(explicit.as_os_str()), Some(dir.as_path())),
            KeyLookup::Env(PrivateKeyPath(explicit)),
            "a usable env key wins"
        );
        assert_eq!(
            lookup(
                Some(OsStr::new("/nonexistent/ipe/key")),
                Some(dir.as_path())
            ),
            KeyLookup::EnvUnusable,
            "an unusable env key refuses; it never falls back to the stored key"
        );
        assert_eq!(
            lookup(Some(OsStr::new("  ")), Some(dir.as_path())),
            KeyLookup::Stored(PrivateKeyPath(stored.clone())),
            "a blank env value counts as unset"
        );
        assert_eq!(
            lookup(None, Some(dir.as_path())),
            KeyLookup::Stored(PrivateKeyPath(stored))
        );
        assert_eq!(lookup(None, None), KeyLookup::Missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsupported_secret_store_generates_no_key() {
        let dir = test_dir("store-unsupported");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            SecretStore::Unsupported,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(result, Err(SetupError::StoreUnsupported)),
            "an unsupported store must refuse, got {result:?}"
        );
        assert_eq!(consent.asked, 0, "nothing is asked before the refusal");
        assert_eq!(registrar.calls, 0, "nothing is registered");
        assert!(dir_entries(&dir).is_empty(), "no key file is written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsupported_secret_store_stages_no_key_file() {
        let dir = test_dir("stage-unsupported");
        let held = create_config_dir(SecretStore::Unsupported, &dir.join("ipe"));
        assert!(
            matches!(held, Err(SetupError::StoreUnsupported)),
            "an unsupported store holds no dir to stage a key in, got {:?}",
            held.as_ref().err()
        );
        drop(held);
        assert!(dir_entries(&dir).is_empty(), "no staged file is written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_config_dir_another_user_can_write_registers_no_key() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = test_dir("dir-exposed");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("chmod world-writable");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(&result, Err(SetupError::NotOwnerOnly(p)) if *p == dir),
            "a world-writable config dir must be refused, got {result:?}"
        );
        assert_eq!(consent.asked, 0, "nothing is asked before the refusal");
        assert_eq!(registrar.calls, 0, "nothing is registered");
        assert!(dir_entries(&dir).is_empty(), "no key file is written");
        let rendered = result.err().map(|e| e.to_string());
        assert!(
            rendered.is_some_and(|text| text.contains(SIGNING_KEY_ENV)),
            "the refusal names the environment-variable way out"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_stored_key_another_user_can_read_is_reported_and_never_used() {
        let dir = test_dir("key-exposed");
        let stored = dir.join(PRIVATE_KEY_FILE);
        plant_with_mode(&stored, b"exposed", 0o644);
        let found = lookup(None, Some(dir.as_path()));
        assert_eq!(found, KeyLookup::StoredExposed(stored.clone()));
        assert_eq!(found.usable(), None, "publish never signs with it");
        let status = status_line(None, Some(dir.as_path()));
        assert!(
            status.contains("not private to you") && status.contains(SIGNING_KEYS_SETTINGS),
            "the status names the exposure and where to revoke the key: {status}"
        );
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(&result, Err(SetupError::StoredKeyExposed(p)) if *p == stored),
            "an exposed stored key must be refused, got {result:?}"
        );
        let rendered = result.err().map(|e| e.to_string());
        assert!(
            rendered.is_some_and(|text| {
                text.contains("already registered") && text.contains(SIGNING_KEYS_SETTINGS)
            }),
            "the refusal says the key is already registered on GitHub and names where to revoke it"
        );
        assert_eq!(consent.asked, 0, "nothing is asked before the refusal");
        assert_eq!(registrar.calls, 0, "nothing is registered");
        assert_eq!(std::fs::read(&stored).expect("read"), b"exposed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_at_the_key_name_is_reported_unusable() {
        let dir = test_dir("key-is-dir");
        let stored = dir.join(PRIVATE_KEY_FILE);
        std::fs::create_dir(&stored).expect("plant dir");
        let found = lookup(None, Some(dir.as_path()));
        assert_eq!(found, KeyLookup::StoredUnusable(stored.clone()));
        assert!(
            status_line(None, Some(dir.as_path())).contains("not a usable key file"),
            "the status names the unusable occupant"
        );
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(&result, Err(SetupError::Occupied(p)) if *p == stored),
            "a directory at the key name must be refused, got {result:?}"
        );
        assert_eq!(consent.asked, 0);
        assert_eq!(registrar.calls, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_dir_is_unusable_never_an_exposed_key() {
        let base = test_dir("dir-linked");
        let real = base.join("real");
        std::fs::create_dir(&real).expect("create real dir");
        plant_with_mode(&real.join(PRIVATE_KEY_FILE), b"key", 0o600);
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant dir symlink");

        let found = lookup(None, Some(link.as_path()));
        assert_eq!(
            found,
            KeyLookup::StoredDirRefused(DirRefusal::Symlinked(link.clone()))
        );
        assert_eq!(found.usable(), None, "publish never signs through the link");
        let status = status_line(None, Some(link.as_path()));
        assert!(
            status.contains("symbolic link") && !status.contains(SIGNING_KEYS_SETTINGS),
            "the status names the link and never asks to revoke the key: {status}"
        );
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&link, false);
        let result = set_up(
            HOST_SECRET_STORE,
            None,
            Some(link.as_path()),
            &mut consent,
            &mut registrar,
        );
        assert!(
            matches!(&result, Err(SetupError::SymlinkedDir(p)) if *p == link),
            "a symlinked config dir must be refused as a link, got {result:?}"
        );
        assert_eq!(consent.asked, 0, "nothing is asked before the refusal");
        assert_eq!(registrar.calls, 0, "nothing is registered");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn a_config_dir_another_user_can_write_is_refused_before_its_key_is_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = test_dir("dir-shared-key");
        plant_with_mode(&dir.join(PRIVATE_KEY_FILE), b"key", 0o600);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("chmod world-writable");
        let found = lookup(None, Some(dir.as_path()));
        assert_eq!(
            found,
            KeyLookup::StoredDirRefused(DirRefusal::Untrusted(dir.clone()))
        );
        assert_eq!(found.usable(), None, "publish never signs with it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_no_terminal_hint_is_the_generic_hint_when_no_key_is_configured() {
        let dir = test_dir("hint-missing");
        assert_eq!(
            no_terminal_hint(None, Some(dir.as_path())),
            Some(crate::text::msg::signing_key_hint_no_terminal())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_no_terminal_hint_is_silent_for_a_usable_stored_key() {
        let dir = test_dir("hint-usable");
        plant_with_mode(&dir.join(PRIVATE_KEY_FILE), b"key", 0o600);
        assert_eq!(
            no_terminal_hint(None, Some(dir.as_path())),
            None,
            "a usable stored key needs no hint"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_no_terminal_hint_shows_the_status_for_an_exposed_stored_key() {
        let dir = test_dir("hint-exposed");
        plant_with_mode(&dir.join(PRIVATE_KEY_FILE), b"exposed", 0o644);
        let hint = no_terminal_hint(None, Some(dir.as_path())).expect("a hint is printed");
        assert!(
            hint.contains("not private to you") && hint.contains(SIGNING_KEYS_SETTINGS),
            "the hint names the exposure and where to revoke the key: {hint}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_no_terminal_hint_shows_the_status_for_an_unusable_stored_key() {
        let dir = test_dir("hint-unusable");
        std::fs::create_dir(dir.join(PRIVATE_KEY_FILE)).expect("plant dir");
        let hint = no_terminal_hint(None, Some(dir.as_path())).expect("a hint is printed");
        assert!(
            hint.contains("not a usable key file"),
            "the hint names the unusable occupant: {hint}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_set_env_var_suppresses_the_offer() {
        let dir = test_dir("env-set");
        let mut consent = Answer {
            yes: true,
            asked: 0,
        };
        let mut registrar = FakeRegistrar::new(&dir, false);
        let outcome = set_up(
            HOST_SECRET_STORE,
            Some(OsStr::new("/nonexistent/ipe/key")),
            Some(dir.as_path()),
            &mut consent,
            &mut registrar,
        )
        .expect("skip");
        assert_eq!(outcome, SetupOutcome::EnvUnusable);
        assert_eq!(consent.asked, 0);
        assert_eq!(registrar.calls, 0);
        assert!(dir_entries(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registration_errors_never_carry_key_material() {
        let pair = GeneratedKeyPair::from_seed(&RFC8032_SEED, 1).expect("encodes");
        let rendered = SetupError::Registration(RegistrationError::Refused {
            status: 422,
            message: "key is already in use".to_owned(),
        })
        .to_string();
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains(pair.private_pem.lines().nth(1).expect("body line")));
    }

    /// Every line after the first of `rendered` is an indented continuation.
    fn only_continuation_lines(rendered: &str) -> bool {
        rendered
            .lines()
            .skip(1)
            .all(|line| line.starts_with(ipe_diagnostics::terminal::CONTINUATION_INDENT))
    }

    #[test]
    fn a_relayed_failure_detail_cannot_forge_an_output_line() {
        let forged = "offline\nipe login: forged success\u{1b}[2K";
        for error in [
            RegistrationError::Authorization(forged.to_owned()),
            RegistrationError::Transport(forged.to_owned()),
            RegistrationError::Refused {
                status: 500,
                message: forged.to_owned(),
            },
        ] {
            let rendered = SetupError::Registration(error).to_string();
            assert!(only_continuation_lines(&rendered), "{rendered:?}");
            assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
        }
        let io = SetupError::Io {
            path: PathBuf::from("/cfg/ipe/\nipe: forged"),
            source: std::io::Error::other(forged),
        }
        .to_string();
        assert!(only_continuation_lines(&io), "{io:?}");
        assert!(!io.contains('\u{1b}'), "{io:?}");
    }

    #[test]
    fn the_status_line_names_where_the_key_comes_from() {
        let dir = test_dir("status");
        let unusable = status_line(
            Some(OsStr::new("/nonexistent/ipe/key")),
            Some(dir.as_path()),
        );
        assert!(unusable.contains(SIGNING_KEY_ENV), "{unusable:?}");
        let missing = status_line(None, Some(dir.as_path()));
        assert!(missing.contains("ipe login --signing-key"), "{missing:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An HTTP answer with `status` and `body`, as the agent hands it back.
    fn answer(status: u16, body: &str) -> ureq::http::Response<ureq::Body> {
        ureq::http::Response::builder()
            .status(status)
            .body(ureq::Body::builder().data(body.as_bytes().to_vec()))
            .unwrap()
    }

    #[test]
    fn only_created_counts_as_registered() {
        assert!(registration_outcome(Ok(answer(201, ""))).is_ok());
        for status in [200, 204, 302, 422, 500] {
            let outcome = registration_outcome(Ok(answer(status, r#"{"message":"no"}"#)));
            assert!(
                matches!(
                    &outcome,
                    Err(RegistrationError::Refused { status: s, message })
                        if *s == status && message == "no"
                ),
                "status {status} must be refused with its message: {outcome:?}"
            );
        }
    }

    #[test]
    fn status_and_transport_errors_are_refusals() {
        assert!(matches!(
            registration_outcome(Err(ureq::Error::StatusCode(401))),
            Err(RegistrationError::Refused { status: 401, .. })
        ));
        assert!(matches!(
            registration_outcome(Err(ureq::Error::Timeout(ureq::Timeout::Global))),
            Err(RegistrationError::Transport(_))
        ));
        assert!(matches!(
            registration_outcome(Err(ureq::Error::TooManyRedirects)),
            Err(RegistrationError::Transport(_))
        ));
    }
}
