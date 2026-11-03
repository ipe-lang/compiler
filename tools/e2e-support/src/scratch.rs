//! A test's scratch tree lives exactly as long as the test.
//!
//! [`fresh`] empties a scratch path and claims it for the calling thread; every
//! claimed path is removed when that thread ends. libtest runs each test on a
//! thread of its own and joins it before it reports, so a claimed tree is gone
//! once its test is, panic or not. An emitted project bundles the whole runtime
//! crate, so a tree left behind per test grows a run's disk with its test
//! count; a claimed tree bounds it by the tests running at once.
//!
//! Claim from the test's own thread (the test body or a helper it calls): a
//! tree claimed on a worker thread is removed when that worker ends.

use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};

/// The paths the current thread claimed, removed when the thread ends.
struct Claimed(RefCell<Vec<PathBuf>>);

impl Drop for Claimed {
    fn drop(&mut self) {
        for path in self.0.get_mut().drain(..).rev() {
            if let Err(e) = std::fs::remove_dir_all(&path)
                && e.kind() != io::ErrorKind::NotFound
            {
                eprintln!(
                    "e2e-support: could not remove scratch tree {}: {e}",
                    path.display()
                );
            }
        }
    }
}

thread_local! {
    static CLAIMED: Claimed = const { Claimed(RefCell::new(Vec::new())) };
}

/// Empty the scratch tree at `path` and remove it when the calling thread ends.
///
/// The emptying keeps a fixed-name tree an earlier run left (a run killed
/// mid-test) out of this one; a tree
/// that is already absent is the expected case.
pub fn fresh(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
    // A thread already tearing its locals down has no later end to remove the
    // tree at; the tree then outlives the test as it did before the claim.
    let _ = CLAIMED.try_with(|claimed| {
        if let Ok(mut paths) = claimed.0.try_borrow_mut()
            && !paths.iter().any(|p| p == path)
        {
            paths.push(path.to_path_buf());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::fresh;

    #[test]
    fn a_claimed_tree_is_removed_when_its_thread_ends() {
        let root = ipe_test_temp::temp_root()
            .join(format!("e2e_support_scratch_claim_{}", std::process::id()));
        let tree = root.join("emitted");
        let worker_tree = tree.clone();
        let removed = std::thread::spawn(move || {
            fresh(&worker_tree);
            std::fs::create_dir_all(worker_tree.join("src")).expect("create the scratch tree");
            std::fs::write(worker_tree.join("src").join("main.rs"), "fn main() {}")
                .expect("write into the scratch tree");
            assert!(worker_tree.join("src").join("main.rs").is_file());
        })
        .join();
        assert!(removed.is_ok(), "the claiming thread ran to its end");
        assert!(
            !tree.exists(),
            "a claimed tree must be gone once its thread ended: {}",
            tree.display()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_claim_empties_a_tree_left_by_an_earlier_run() {
        let root = ipe_test_temp::temp_root()
            .join(format!("e2e_support_scratch_stale_{}", std::process::id()));
        let tree = root.join("emitted");
        std::fs::create_dir_all(&tree).expect("create the stale tree");
        std::fs::write(tree.join("stale.rs"), "").expect("write the stale file");
        let worker_tree = tree.clone();
        let seen = std::thread::spawn(move || {
            fresh(&worker_tree);
            worker_tree.exists()
        })
        .join();
        assert!(
            matches!(seen, Ok(false)),
            "a claim must empty the earlier run's tree before the test writes"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
