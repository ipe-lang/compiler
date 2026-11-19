//! A read-only git smart-HTTP server over TLS on loopback, for tests that fetch an index source.
//!
//! An index `source` is an `https://` or `ssh://` URL, so a test that fetches
//! a package serves its fixture repository through [`GitHttpsFixture`] and
//! records the returned [`RepoUrl`]. The client trusts the fixture through the
//! pairs of [`GitHttpsFixture::client_env`]; TLS verification stays on.
//!
//! Each connection carries one request, parsed once into a [`Route`] whose
//! repository is a [`RepoId`] index, so a request path never names a
//! filesystem location. Only the upload side of the smart protocol is served;
//! `git http-backend` answers it as a CGI child under a cleared environment.
//! Every read is bounded in bytes and time by the named `const` ceilings.
//!
//! The certificates under `certs/` are test-only material, generated once and
//! embedded; the CA key was discarded after signing the leaf:
//!
//! ```text
//! openssl ecparam -name prime256v1 -genkey -noout -out ca.key
//! openssl req -x509 -new -key ca.key -subj "/CN=ipe git-https-fixture test CA" \
//!     -days 2912120 -addext basicConstraints=critical,CA:TRUE \
//!     -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem
//! openssl ecparam -name prime256v1 -genkey -noout -out leaf.ec
//! openssl pkcs8 -topk8 -nocrypt -in leaf.ec -out leaf.key
//! openssl req -new -key leaf.key -subj "/CN=localhost" -out leaf.csr
//! printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
//! extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' > leaf.ext
//! openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
//!     -days 2912120 -extfile leaf.ext -out leaf.pem
//! ```
//!
//! Both certificates expire on 9999-12-31.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The most repositories one fixture serves.
pub const MAX_REPOS: usize = 64;

/// The largest request head read, request line and headers together.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The largest request body admitted, by its declared `Content-Length`.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// The most connections served at once; a further one is closed unanswered.
const MAX_CONCURRENT: usize = 4;

/// The most connections one fixture accepts over its life.
const MAX_CONNECTIONS: usize = 512;

/// The read and write timeout of every client socket.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// The most CGI output read for one response.
const MAX_CGI_STDOUT: u64 = 64 * 1024 * 1024;

/// The wall time one CGI child may run.
const CGI_WALL_TIME: Duration = Duration::from_secs(30);

/// The most headers one request may carry.
const MAX_HEADERS: usize = 64;

/// The interval at which a running child is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The hosts a client must reach without a proxy.
const LOOPBACK_HOSTS: &str = "127.0.0.1,localhost";

/// The CGI response headers passed to the client; every other one is dropped.
const PASSED_HEADERS: [&str; 4] = ["Content-Type", "Cache-Control", "Expires", "Pragma"];

/// The test CA the client trusts.
const CA_PEM: &str = include_str!("../certs/ca.pem");

/// The leaf certificate the fixture presents, for `127.0.0.1` and `localhost`.
const LEAF_PEM: &str = include_str!("../certs/leaf.pem");

/// The leaf's private key.
const LEAF_KEY: &str = include_str!("../certs/leaf.key");

/// The process-wide CA file, written once so every trust taken in this process stays valid.
static CA_FILE: OnceLock<Result<PathBuf, io::ErrorKind>> = OnceLock::new();

/// Why a fixture could not start.
#[derive(Debug)]
pub enum FixtureError {
    /// The loopback listener could not be bound.
    Bind(io::Error),
    /// The TLS configuration was refused.
    Tls(rustls::Error),
    /// An embedded PEM object did not decode.
    Pem(&'static str),
    /// A path to serve is neither a worktree with `.git` nor a bare git directory.
    NotARepo(PathBuf),
    /// More than [`MAX_REPOS`] repositories were named.
    TooManyRepos,
    /// The accept thread could not start.
    Thread(io::Error),
    /// `git http-backend` cannot start on this host.
    Backend(io::Error),
    /// The CA file the client trusts could not be written.
    CaFile(io::Error),
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(error) => write!(f, "cannot bind the loopback listener: {error}"),
            Self::Tls(error) => write!(f, "the TLS configuration is refused: {error}"),
            Self::Pem(what) => write!(f, "the embedded {what} does not decode"),
            Self::NotARepo(path) => write!(f, "{} is not a git repository", path.display()),
            Self::TooManyRepos => write!(f, "a fixture serves at most {MAX_REPOS} repositories"),
            Self::Thread(error) => write!(f, "cannot start the accept thread: {error}"),
            Self::Backend(error) => write!(f, "`git http-backend` cannot start: {error}"),
            Self::CaFile(error) => write!(f, "cannot write the test CA file: {error}"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// The `https://` URL of one served repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoUrl(String);

impl RepoUrl {
    /// The URL's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RepoUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A running fixture; dropping it stops the server and joins every thread.
pub struct GitHttpsFixture {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    /// The live handler count the ceiling tests observe.
    #[cfg(test)]
    active: Arc<AtomicUsize>,
    accept: Option<JoinHandle<()>>,
    ca_file: PathBuf,
}

impl GitHttpsFixture {
    /// Serve `repos` read-only, returning one URL per repository in order.
    ///
    /// Each path is a worktree holding `.git` or a bare git directory,
    /// resolved once to an absolute git directory.
    ///
    /// # Errors
    ///
    /// A [`FixtureError`] naming the step that failed; nothing is served then.
    pub fn start(repos: &[&Path]) -> Result<(Self, Vec<RepoUrl>), FixtureError> {
        if repos.len() > MAX_REPOS {
            return Err(FixtureError::TooManyRepos);
        }
        let git_dirs = repos
            .iter()
            .map(|repo| git_dir(repo))
            .collect::<Result<Vec<_>, _>>()?;
        let backend = Backend::probe()?;
        let config = Arc::new(server_config()?);
        let ca_file = ca_file()?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(FixtureError::Bind)?;
        let addr = listener.local_addr().map_err(FixtureError::Bind)?;
        let urls = (0..git_dirs.len())
            .map(|id| RepoUrl(format!("https://{addr}/r/{id}")))
            .collect();
        let served = Arc::new(Served {
            git_dirs,
            backend,
            config,
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let accept = {
            let shutdown = Arc::clone(&shutdown);
            let active = Arc::clone(&active);
            std::thread::Builder::new()
                .name("git-https-fixture-accept".to_owned())
                .spawn(move || accept_loop(&listener, &served, &shutdown, &active))
                .map_err(FixtureError::Thread)?
        };
        let fixture = Self {
            addr,
            shutdown,
            #[cfg(test)]
            active,
            accept: Some(accept),
            ca_file,
        };
        Ok((fixture, urls))
    }

    /// The environment a client git needs to trust and reach this fixture.
    ///
    /// The pairs are `GIT_SSL_CAINFO`, `NO_PROXY` and `no_proxy`; they are the
    /// one source for an in-process trust and for a spawned child alike.
    #[must_use]
    pub fn client_env(&self) -> [(&'static str, OsString); 3] {
        [
            ("GIT_SSL_CAINFO", self.ca_file.clone().into_os_string()),
            ("NO_PROXY", OsString::from(LOOPBACK_HOSTS)),
            ("no_proxy", OsString::from(LOOPBACK_HOSTS)),
        ]
    }
}

impl Drop for GitHttpsFixture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // One connection wakes the blocked accept so it sees the flag.
        let _wake = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(accept) = self.accept.take() {
            let _joined = accept.join();
        }
    }
}

/// What every connection handler shares.
struct Served {
    git_dirs: Vec<PathBuf>,
    backend: Backend,
    config: Arc<ServerConfig>,
}

/// The `git http-backend` program and the one directory its children search.
struct Backend {
    program: PathBuf,
    exec_path: OsString,
}

impl Backend {
    /// Locate `git http-backend` and prove it starts and exits.
    fn probe() -> Result<Self, FixtureError> {
        let git = ipe_sandbox::host_tool::resolve(ipe_sandbox::HostTool::Git)
            .map_err(|refusal| FixtureError::Backend(io::Error::other(refusal)))?;
        let out = git
            .command()
            .arg("--exec-path")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(FixtureError::Backend)?;
        if !out.status.success() {
            return Err(FixtureError::Backend(io::Error::other(
                "`git --exec-path` failed",
            )));
        }
        let exec_path = String::from_utf8(out.stdout)
            .map_err(|_| FixtureError::Backend(io::Error::other("the git exec path is not UTF-8")))?
            .trim_end()
            .to_owned();
        let backend = Self {
            program: Path::new(&exec_path).join("git-http-backend"),
            exec_path: OsString::from(exec_path),
        };
        let mut child = Command::new(&backend.program)
            .env_clear()
            .env("PATH", &backend.exec_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(FixtureError::Backend)?;
        match wait_until(&mut child, Instant::now() + CGI_WALL_TIME) {
            Ok(Some(_)) => Ok(backend),
            Ok(None) => Err(FixtureError::Backend(io::Error::from(
                io::ErrorKind::TimedOut,
            ))),
            Err(error) => Err(FixtureError::Backend(error)),
        }
    }
}

/// The absolute git directory `repo` names.
fn git_dir(repo: &Path) -> Result<PathBuf, FixtureError> {
    let not_a_repo = || FixtureError::NotARepo(repo.to_path_buf());
    let dot_git = repo.join(".git");
    let dir = if dot_git.is_dir() {
        dot_git
    } else if repo.join("HEAD").is_file() && repo.join("objects").is_dir() {
        repo.to_path_buf()
    } else {
        return Err(not_a_repo());
    };
    dir.canonicalize().map_err(|_| not_a_repo())
}

/// The TLS server configuration: the embedded leaf on the `ring` provider, no client auth.
fn server_config() -> Result<ServerConfig, FixtureError> {
    let chain = CertificateDer::pem_slice_iter(LEAF_PEM.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FixtureError::Pem("leaf certificate"))?;
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY.as_bytes())
        .map_err(|_| FixtureError::Pem("leaf key"))?;
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(FixtureError::Tls)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(FixtureError::Tls)
}

/// The CA file under the test temp root, written once per process.
fn ca_file() -> Result<PathBuf, FixtureError> {
    CA_FILE
        .get_or_init(|| write_ca_file().map_err(|error| error.kind()))
        .clone()
        .map_err(|kind| FixtureError::CaFile(io::Error::from(kind)))
}

/// Write the embedded CA to this process's own directory under the test temp root.
fn write_ca_file() -> io::Result<PathBuf> {
    let dir = ipe_test_temp::temp_root().join(format!("git-https-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("ca.pem");
    std::fs::write(&path, CA_PEM)?;
    Ok(path)
}

/// Decrements the live connection count when its handler ends, however it ends.
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections until shutdown, holding the concurrent and total ceilings.
fn accept_loop(
    listener: &TcpListener,
    served: &Arc<Served>,
    shutdown: &AtomicBool,
    active: &Arc<AtomicUsize>,
) {
    let mut handlers = Vec::new();
    let mut total = 0_usize;
    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            break;
        };
        total = total.saturating_add(1);
        if total > MAX_CONNECTIONS || active.load(Ordering::SeqCst) >= MAX_CONCURRENT {
            let _closed = stream.shutdown(Shutdown::Both);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let guard = ActiveGuard(Arc::clone(active));
        let served = Arc::clone(served);
        // A refused spawn drops the closure, and with it the guard and the stream.
        if let Ok(handler) = std::thread::Builder::new()
            .name("git-https-fixture-conn".to_owned())
            .spawn(move || {
                let _guard = guard;
                serve(stream, &served);
            })
        {
            handlers.push(handler);
        }
    }
    for handler in handlers {
        let _joined = handler.join();
    }
}

/// One request's route: an upload-side smart-HTTP endpoint of one served repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// `GET /r/<id>/info/refs?service=git-upload-pack`.
    InfoRefs { repo: RepoId },
    /// `POST /r/<id>/git-upload-pack`.
    UploadPack { repo: RepoId },
}

/// The index of a served repository, below the served count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RepoId(u8);

impl RepoId {
    /// The id `raw` spells, when it is a plain decimal below `served`.
    fn parse(raw: &str, served: usize) -> Option<Self> {
        if raw.is_empty() || raw.len() > 2 || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let id = raw.parse::<u8>().ok()?;
        (usize::from(id) < served).then_some(Self(id))
    }

    /// The id as an index into the served repositories.
    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// A response status the fixture itself decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    BadRequest,
    Forbidden,
    NotFound,
    LengthRequired,
    PayloadTooLarge,
    HeaderFieldsTooLarge,
    BadGateway,
    GatewayTimeout,
}

impl Refused {
    /// The status line text after the HTTP version.
    const fn status(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::LengthRequired => "411 Length Required",
            Self::PayloadTooLarge => "413 Payload Too Large",
            Self::HeaderFieldsTooLarge => "431 Request Header Fields Too Large",
            Self::BadGateway => "502 Bad Gateway",
            Self::GatewayTimeout => "504 Gateway Timeout",
        }
    }
}

/// Why a connection ends: answered with a status, or closed with no response.
enum Ending {
    Answer(Refused),
    Close,
}

/// One parsed request.
struct Request {
    route: Route,
    content_type: Option<String>,
    git_protocol: Option<String>,
    gzip: bool,
    body: Vec<u8>,
}

/// A response ready to write.
struct Response {
    status: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// An empty response with a status the fixture decided.
    fn refused(refused: Refused) -> Self {
        Self {
            status: refused.status().to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// Serve one connection: one request, one response, then close.
fn serve(stream: TcpStream, served: &Served) {
    if stream.set_read_timeout(Some(SOCKET_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(SOCKET_TIMEOUT)).is_err()
    {
        return;
    }
    let Ok(connection) = ServerConnection::new(Arc::clone(&served.config)) else {
        return;
    };
    let mut tls = StreamOwned::new(connection, stream);
    let response = match read_request(&mut tls, served.git_dirs.len()) {
        Ok(request) => run_cgi(served, request),
        Err(Ending::Answer(refused)) => Response::refused(refused),
        Err(Ending::Close) => return,
    };
    let _written = write_response(&mut tls, &response);
}

/// Read and parse one request under the head and body ceilings.
fn read_request(tls: &mut impl Read, served: usize) -> Result<Request, Ending> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = tls.read(&mut chunk).map_err(|_| Ending::Close)?;
        if read == 0 {
            return Err(Ending::Close);
        }
        head.extend_from_slice(chunk.get(..read).unwrap_or_default());
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut headers);
        match parsed.parse(&head) {
            Ok(httparse::Status::Complete(len)) => {
                if len > MAX_HEAD_BYTES {
                    return Err(Ending::Answer(Refused::HeaderFieldsTooLarge));
                }
                let prefix = head.get(len..).unwrap_or_default();
                return complete_request(&parsed, prefix, tls, served);
            }
            Ok(httparse::Status::Partial) => {
                if head.len() > MAX_HEAD_BYTES {
                    return Err(Ending::Answer(Refused::HeaderFieldsTooLarge));
                }
            }
            Err(httparse::Error::TooManyHeaders) => {
                return Err(Ending::Answer(Refused::HeaderFieldsTooLarge));
            }
            Err(_) => return Err(Ending::Answer(Refused::BadRequest)),
        }
    }
}

/// The one value of header `name`, refusing a duplicate or a non-UTF-8 value.
fn header<'a>(parsed: &httparse::Request<'_, 'a>, name: &str) -> Result<Option<&'a str>, Ending> {
    let mut found = None;
    for field in parsed.headers.iter() {
        if field.name.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(Ending::Answer(Refused::BadRequest));
            }
            let value = std::str::from_utf8(field.value)
                .map_err(|_| Ending::Answer(Refused::BadRequest))?;
            found = Some(value.trim());
        }
    }
    Ok(found)
}

/// Route a parsed head and read its body, `prefix` being the body bytes already read.
fn complete_request(
    parsed: &httparse::Request<'_, '_>,
    prefix: &[u8],
    tls: &mut impl Read,
    served: usize,
) -> Result<Request, Ending> {
    let (Some(method), Some(path)) = (parsed.method, parsed.path) else {
        return Err(Ending::Answer(Refused::BadRequest));
    };
    let route = route(method, path, served).map_err(Ending::Answer)?;
    if parsed
        .headers
        .iter()
        .any(|field| field.name.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        return Err(Ending::Answer(Refused::LengthRequired));
    }
    let declared = match header(parsed, "Content-Length")? {
        None => 0,
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| Ending::Answer(Refused::BadRequest))?,
    };
    if declared > MAX_BODY_BYTES {
        return Err(Ending::Answer(Refused::PayloadTooLarge));
    }
    let prefix_len = u64::try_from(prefix.len()).map_err(|_| Ending::Close)?;
    let Some(remaining) = declared.checked_sub(prefix_len) else {
        return Err(Ending::Answer(Refused::BadRequest));
    };
    let mut body = prefix.to_vec();
    tls.take(remaining)
        .read_to_end(&mut body)
        .map_err(|_| Ending::Close)?;
    if u64::try_from(body.len()).ok() != Some(declared) {
        return Err(Ending::Close);
    }
    let git_protocol = header(parsed, "Git-Protocol")?
        .filter(|value| matches!(*value, "version=2" | "version=1" | "version=0"))
        .map(str::to_owned);
    let gzip = header(parsed, "Content-Encoding")? == Some("gzip");
    Ok(Request {
        route,
        content_type: header(parsed, "Content-Type")?.map(str::to_owned),
        git_protocol,
        gzip,
        body,
    })
}

/// The route `method` and `path` name, or the status refusing them.
fn route(method: &str, path: &str, served: usize) -> Result<Route, Refused> {
    let (resource, query) = path.split_once('?').unwrap_or((path, ""));
    if resource.ends_with("/git-receive-pack") || query.contains("git-receive-pack") {
        return Err(Refused::Forbidden);
    }
    let Some((id, endpoint)) = resource
        .strip_prefix("/r/")
        .and_then(|rest| rest.split_once('/'))
    else {
        return Err(Refused::NotFound);
    };
    let repo = RepoId::parse(id, served).ok_or(Refused::NotFound)?;
    match (method, endpoint, query) {
        ("GET", "info/refs", "service=git-upload-pack") => Ok(Route::InfoRefs { repo }),
        ("POST", "git-upload-pack", "") => Ok(Route::UploadPack { repo }),
        _ => Err(Refused::NotFound),
    }
}

/// Answer `request` through a `git http-backend` child, bounded in output and wall time.
fn run_cgi(served: &Served, request: Request) -> Response {
    let (repo, endpoint, method, query) = match request.route {
        Route::InfoRefs { repo } => (repo, "info/refs", "GET", "service=git-upload-pack"),
        Route::UploadPack { repo } => (repo, "git-upload-pack", "POST", ""),
    };
    let Some(git_dir) = served.git_dirs.get(repo.index()) else {
        return Response::refused(Refused::NotFound);
    };
    let mut command = Command::new(&served.backend.program);
    command
        .env_clear()
        .env("PATH", &served.backend.exec_path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("PATH_TRANSLATED", git_dir.join(endpoint))
        .env("REQUEST_METHOD", method)
        .env("QUERY_STRING", query)
        .env(
            "CONTENT_TYPE",
            request.content_type.as_deref().unwrap_or_default(),
        )
        .env("CONTENT_LENGTH", request.body.len().to_string())
        .current_dir(git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(protocol) = &request.git_protocol {
        command.env("GIT_PROTOCOL", protocol);
    }
    if request.gzip {
        command.env("HTTP_CONTENT_ENCODING", "gzip");
    }
    let deadline = Instant::now() + CGI_WALL_TIME;
    let Ok(mut child) = command.spawn() else {
        return Response::refused(Refused::BadGateway);
    };
    let output = bounded_output(&mut child, request.body, deadline);
    let status = match &output {
        Ok(_) => wait_until(&mut child, deadline).ok().flatten(),
        Err(_) => None,
    };
    if status.is_none() {
        let _killed = child.kill();
        let _reaped = child.wait();
    }
    match (output, status) {
        (Ok(out), Some(_)) => cgi_response(&out),
        (Err(refused), _) => Response::refused(refused),
        (Ok(_), None) => Response::refused(Refused::GatewayTimeout),
    }
}

/// Feed `body` to the child and read its output under [`MAX_CGI_STDOUT`] by `deadline`.
///
/// On a refusal the feeding and reading threads are left to end on their own:
/// once the caller kills the child, its pipes close and both threads return.
fn bounded_output(child: &mut Child, body: Vec<u8>, deadline: Instant) -> Result<Vec<u8>, Refused> {
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(Refused::BadGateway);
    };
    let feeder = std::thread::Builder::new()
        .name("git-https-fixture-feed".to_owned())
        .spawn(move || {
            let _fed = stdin.write_all(&body);
        })
        .map_err(|_| Refused::BadGateway)?;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::Builder::new()
        .name("git-https-fixture-read".to_owned())
        .spawn(move || {
            let mut out = Vec::new();
            let read = stdout
                .take(MAX_CGI_STDOUT.saturating_add(1))
                .read_to_end(&mut out)
                .map(|_| out);
            let _sent = sender.send(read);
        })
        .map_err(|_| Refused::BadGateway)?;
    let waited = deadline.saturating_duration_since(Instant::now());
    let out = match receiver.recv_timeout(waited) {
        Ok(Ok(out)) => out,
        Ok(Err(_)) => return Err(Refused::BadGateway),
        Err(_) => return Err(Refused::GatewayTimeout),
    };
    if u64::try_from(out.len()).map_or(true, |len| len > MAX_CGI_STDOUT) {
        return Err(Refused::BadGateway);
    }
    let _fed = feeder.join();
    let _read = reader.join();
    Ok(out)
}

/// Wait for `child` until `deadline`; `None` when it is still running then.
fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The response a CGI output describes: its `Status:`, the passed headers, and its body.
fn cgi_response(out: &[u8]) -> Response {
    let split = out
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| (at, at.saturating_add(4)))
        .or_else(|| {
            out.windows(2)
                .position(|window| window == b"\n\n")
                .map(|at| (at, at.saturating_add(2)))
        });
    let Some((head_end, body_start)) = split else {
        return Response::refused(Refused::BadGateway);
    };
    let Some(head) = out
        .get(..head_end)
        .and_then(|head| std::str::from_utf8(head).ok())
    else {
        return Response::refused(Refused::BadGateway);
    };
    let mut status = "200 OK".to_owned();
    let mut headers = Vec::new();
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Response::refused(Refused::BadGateway);
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Status") {
            if !value.bytes().take(3).all(|b| b.is_ascii_digit()) || value.len() < 3 {
                return Response::refused(Refused::BadGateway);
            }
            value.clone_into(&mut status);
        } else if PASSED_HEADERS
            .iter()
            .any(|passed| passed.eq_ignore_ascii_case(name))
        {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    Response {
        status,
        headers,
        body: out.get(body_start..).unwrap_or_default().to_vec(),
    }
}

/// Write `response` with `Connection: close`, then end the TLS session and the socket's write side.
fn write_response(
    tls: &mut StreamOwned<ServerConnection, TcpStream>,
    response: &Response,
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {}\r\n", response.status);
    for (name, value) in &response.headers {
        let _written = write!(head, "{name}: {value}\r\n");
    }
    let _written = write!(
        head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    );
    tls.write_all(head.as_bytes())?;
    tls.write_all(&response.body)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    while tls.conn.wants_write() {
        tls.conn.write_tls(&mut tls.sock)?;
    }
    tls.sock.shutdown(Shutdown::Write)
}

#[cfg(test)]
mod tests {
    use super::{
        CA_PEM, GitHttpsFixture, MAX_BODY_BYTES, MAX_CONCURRENT, MAX_CONNECTIONS, MAX_HEAD_BYTES,
        RepoUrl,
    };
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    /// A git command blind to the developer's configuration.
    fn git(dir: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .env("GIT_TERMINAL_PROMPT", "0");
        command
    }

    /// A fixture repository with one commit at HEAD.
    #[allow(clippy::expect_used)] // a fixture that cannot be built is a failed test
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new_in(ipe_test_temp::temp_root()).expect("temp dir");
        for args in [
            &["init", "--quiet"][..],
            &["commit", "--quiet", "--allow-empty", "-m", "seed"][..],
        ] {
            let status = git(dir.path()).args(args).status().expect("git runs");
            assert!(status.success(), "git {args:?}");
        }
        dir
    }

    /// A fixture serving one fresh repository.
    #[allow(clippy::expect_used)] // a fixture that cannot start is a failed test
    fn serve_one() -> (tempfile::TempDir, GitHttpsFixture, RepoUrl) {
        let dir = repo();
        let (fixture, urls) = GitHttpsFixture::start(&[dir.path()]).expect("fixture starts");
        let url = urls.into_iter().next().expect("one url");
        (dir, fixture, url)
    }

    /// A TLS client configuration trusting only the test CA.
    #[allow(clippy::expect_used)] // the embedded CA is a constant
    fn client_config() -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(CA_PEM.as_bytes()) {
            roots
                .add(cert.expect("CA decodes"))
                .expect("CA is a trust anchor");
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        Arc::new(config)
    }

    /// Read `stream` until it ends or fails, returning every byte read.
    fn drain(stream: &mut impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut chunk) {
            if read == 0 {
                break;
            }
            out.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        out
    }

    /// Send `raw` over TLS to `addr` and return every response byte.
    #[allow(clippy::expect_used)] // a refused connect is a failed test
    fn exchange(addr: SocketAddr, raw: &[u8]) -> Vec<u8> {
        let name = ServerName::try_from("localhost").expect("server name");
        let connection = ClientConnection::new(client_config(), name).expect("client");
        let socket = TcpStream::connect(addr).expect("connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut tls = StreamOwned::new(connection, socket);
        if tls.write_all(raw).and_then(|()| tls.flush()).is_err() {
            return drain(&mut tls);
        }
        drain(&mut tls)
    }

    /// The status code a raw response opens with.
    fn status(response: &[u8]) -> Option<u16> {
        let text = std::str::from_utf8(response.get(..12)?).ok()?;
        text.strip_prefix("HTTP/1.1 ")?.parse().ok()
    }

    /// The listener address of `url`.
    #[allow(clippy::expect_used)] // the fixture's own URL
    fn addr(url: &RepoUrl) -> SocketAddr {
        let host = url
            .as_str()
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .expect("host");
        host.parse().expect("socket address")
    }

    /// Wait until no handler of `fixture` runs.
    fn settle(fixture: &GitHttpsFixture) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while fixture.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fixture.active.load(Ordering::SeqCst), 0, "handlers settle");
    }

    const INFO_REFS: &str =
        "GET /r/0/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost\r\n\r\n";

    /// A real git client lists the served repository's HEAD over the fixture URL.
    #[allow(clippy::expect_used)] // git that does not run is a failed test
    #[test]
    fn git_lists_the_served_head() {
        let (_dir, fixture, url) = serve_one();
        let cwd = repo();
        let out = git(cwd.path())
            .envs(fixture.client_env())
            .args(["ls-remote", "--", url.as_str()])
            .output()
            .expect("git runs");
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("HEAD"),
            "{out:?}"
        );
    }

    #[test]
    fn a_valid_info_refs_request_is_answered() {
        let (_dir, _fixture, url) = serve_one();
        let response = exchange(addr(&url), INFO_REFS.as_bytes());
        assert_eq!(status(&response), Some(200));
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("application/x-git-upload-pack-advertisement"),
            "{text}"
        );
        assert!(text.contains("Connection: close"), "{text}");
    }

    #[test]
    fn a_head_past_its_ceiling_is_refused() {
        let (_dir, _fixture, url) = serve_one();
        let open = "GET /r/0/info/refs?service=git-upload-pack HTTP/1.1\r\nX-Pad: ";
        let close = "\r\n\r\n";
        let pad = (MAX_HEAD_BYTES + 1).saturating_sub(open.len() + close.len());
        let raw = format!("{open}{}{close}", "a".repeat(pad));
        assert_eq!(raw.len(), MAX_HEAD_BYTES + 1);
        assert_eq!(status(&exchange(addr(&url), raw.as_bytes())), Some(431));
    }

    #[test]
    fn a_body_past_its_ceiling_is_refused() {
        let (_dir, _fixture, url) = serve_one();
        let raw = format!(
            "POST /r/0/git-upload-pack HTTP/1.1\r\nContent-Type: application/x-git-upload-pack-request\r\n\
             Content-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(status(&exchange(addr(&url), raw.as_bytes())), Some(413));
    }

    #[test]
    fn a_chunked_body_is_refused() {
        let (_dir, _fixture, url) = serve_one();
        let raw =
            "POST /r/0/git-upload-pack HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(status(&exchange(addr(&url), raw.as_bytes())), Some(411));
    }

    #[test]
    fn the_receive_side_is_forbidden() {
        let (_dir, _fixture, url) = serve_one();
        for raw in [
            "POST /r/0/git-receive-pack HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            "GET /r/0/info/refs?service=git-receive-pack HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                status(&exchange(addr(&url), raw.as_bytes())),
                Some(403),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_path_outside_the_served_set_is_not_found() {
        let (_dir, _fixture, url) = serve_one();
        for raw in [
            "GET /r/9/info/refs?service=git-upload-pack HTTP/1.1\r\n\r\n",
            "GET /../info/refs?service=git-upload-pack HTTP/1.1\r\n\r\n",
            "GET /r/00/info/refs?service=git-upload-pack HTTP/1.1\r\n\r\n",
            "GET /r/0/HEAD HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                status(&exchange(addr(&url), raw.as_bytes())),
                Some(404),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_plaintext_request_gets_no_http_response() {
        let (_dir, _fixture, url) = serve_one();
        let mut socket = TcpStream::connect(addr(&url)).expect("connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let _sent = socket.write_all(INFO_REFS.as_bytes());
        let response = drain(&mut socket);
        assert!(!response.starts_with(b"HTTP/"), "{response:?}");
    }

    #[test]
    fn a_connection_past_the_concurrent_ceiling_is_closed_unanswered() {
        let (_dir, fixture, url) = serve_one();
        let held: Vec<TcpStream> = (0..MAX_CONCURRENT)
            .map(|_| TcpStream::connect(addr(&url)).expect("connect"))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(20);
        while fixture.active.load(Ordering::SeqCst) < MAX_CONCURRENT && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut extra = TcpStream::connect(addr(&url)).expect("connect");
        extra
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut byte = [0_u8; 1];
        let read = extra.read(&mut byte);
        assert!(
            matches!(&read, Ok(0))
                || matches!(&read, Err(error) if !matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
            "{read:?}"
        );
        drop(held);
        settle(&fixture);
        assert_eq!(
            status(&exchange(addr(&url), INFO_REFS.as_bytes())),
            Some(200)
        );
    }

    #[test]
    fn a_connection_past_the_total_ceiling_is_closed_unanswered() {
        let (_dir, fixture, url) = serve_one();
        assert_eq!(
            status(&exchange(addr(&url), INFO_REFS.as_bytes())),
            Some(200)
        );
        for _ in 1..MAX_CONNECTIONS {
            drop(TcpStream::connect(addr(&url)).expect("connect"));
        }
        settle(&fixture);
        assert!(exchange(addr(&url), INFO_REFS.as_bytes()).is_empty());
    }
}
