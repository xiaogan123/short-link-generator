//! Synthetic Windows Credential Manager continuity across real child processes.
//! This uses a fresh test service and never touches the production namespace.

use std::{
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MODE: &str = "SLG_NATIVE_CREDENTIAL_TEST_MODE";
const SERVICE: &str = "SLG_NATIVE_CREDENTIAL_TEST_SERVICE";
const ACCOUNT: &str = "SLG_NATIVE_CREDENTIAL_TEST_ACCOUNT";
const INITIAL: &str = "synthetic-initial-value";
const UPDATED: &str = "synthetic-updated-value";

struct CredentialCleanup {
    service: String,
    account: String,
}

impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        if let Ok(entry) = keyring::Entry::new(&self.service, &self.account) {
            let _ = entry.delete_credential();
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_child(mode: &str, service: &str, account: &str) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_credential_native_tests::native_credential_child",
        ])
        .env(MODE, mode)
        .env(SERVICE, service)
        .env(ACCOUNT, account)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "synthetic credential child failed");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "synthetic credential child timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn native_credential_child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let service = std::env::var(SERVICE).unwrap();
    let account = std::env::var(ACCOUNT).unwrap();
    let entry = keyring::Entry::new(&service, &account).unwrap();
    match mode.as_str() {
        "read_then_write" => {
            assert!(entry.get_password().is_ok_and(|value| value == INITIAL));
            entry.set_password(UPDATED).unwrap();
        }
        "confirm_missing" => {
            assert!(matches!(entry.get_password(), Err(keyring::Error::NoEntry)));
        }
        _ => panic!("unknown synthetic credential child mode"),
    }
}

#[test]
fn credential_manager_persists_across_processes_and_deletes() {
    let nonce = rand::random::<u64>();
    let service = format!(
        "org.shortlink.generator.synthetic-test.{}.{}",
        std::process::id(),
        nonce
    );
    let account = format!("token:synthetic-{nonce}");
    let _cleanup = CredentialCleanup {
        service: service.clone(),
        account: account.clone(),
    };
    let entry = keyring::Entry::new(&service, &account).unwrap();
    entry.set_password(INITIAL).unwrap();

    run_child("read_then_write", &service, &account);
    assert!(entry.get_password().is_ok_and(|value| value == UPDATED));
    entry.delete_credential().unwrap();
    run_child("confirm_missing", &service, &account);
}
