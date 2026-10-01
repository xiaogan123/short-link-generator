//! Windows-only exclusive lifetime for one local configuration directory.

use std::{
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const LOCK_NAME: &str = "credential-session.lock";

pub(crate) struct ConfigurationLease {
    // OpenOptions creates a non-inheritable Windows handle. Keep it open for the
    // complete Backend lifetime; Windows closes it even if the process crashes.
    _file: File,
}

impl ConfigurationLease {
    pub(crate) fn acquire(directory: &Path) -> Result<Self, String> {
        ensure_plain_directory(directory)?;
        let lock_path = directory.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // No other process may open, replace, or delete this file while the
            // handle exists. OPEN_REPARSE_POINT validates the link itself.
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&lock_path)
            .map_err(|_| "另一个本机客户端正在运行，或无法建立本机配置锁")?;
        let info = file.metadata().map_err(|_| "无法核对本机配置锁")?;
        if !info.is_file() || is_reparse(&info) {
            return Err("本机配置锁的文件类型无效".into());
        }
        // Catch a directory substitution that happened while opening the lock.
        ensure_plain_directory(directory)?;
        // Never unlink the lock: a new file identity could allow two writers.
        Ok(Self { _file: file })
    }
}

fn is_reparse(info: &fs::Metadata) -> bool {
    info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn ensure_plain_directory(directory: &Path) -> Result<(), String> {
    if !directory.is_absolute() {
        return Err("本机配置目录必须是绝对路径".into());
    }
    let mut checked = PathBuf::new();
    for component in directory.components() {
        match component {
            Component::Prefix(_) => checked.push(component.as_os_str()),
            Component::RootDir => {
                checked.push(component.as_os_str());
                check_directory(&checked, false)?;
            }
            Component::Normal(_) => {
                checked.push(component.as_os_str());
                check_directory(&checked, true)?;
            }
            Component::CurDir | Component::ParentDir => {
                return Err("本机配置目录路径无效".into());
            }
        }
    }
    Ok(())
}

fn check_directory(path: &Path, may_create: bool) -> Result<(), String> {
    let info = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(error) if error.kind() == ErrorKind::NotFound && may_create => {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err("无法建立本机配置目录".into()),
            }
            fs::symlink_metadata(path).map_err(|_| "无法核对本机配置目录")?
        }
        Err(_) => return Err("无法核对本机配置目录".into()),
    };
    if !info.is_dir() || is_reparse(&info) {
        return Err("本机配置目录不能经过重解析点或符号链接".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::fs::symlink_file,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    const MODE: &str = "SLG_WINDOWS_LEASE_TEST_MODE";
    const DIRECTORY: &str = "SLG_WINDOWS_LEASE_TEST_DIRECTORY";
    const EXPECT_SUCCESS: &str = "SLG_WINDOWS_LEASE_TEST_EXPECT_SUCCESS";

    fn probe(directory: &Path, expect_success: bool) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_configuration::tests::child_lease_probe"])
            .env(MODE, "probe")
            .env(DIRECTORY, directory)
            .env(EXPECT_SUCCESS, if expect_success { "1" } else { "0" })
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child lease probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn child_lease_probe() {
        let Ok(mode) = std::env::var(MODE) else {
            return;
        };
        let directory = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
        if mode == "probe" {
            let acquired = ConfigurationLease::acquire(&directory);
            assert_eq!(
                acquired.is_ok(),
                std::env::var(EXPECT_SUCCESS).unwrap() == "1"
            );
        } else if mode == "hold" {
            let _lease = ConfigurationLease::acquire(&directory).unwrap();
            fs::write(directory.join("child-ready"), b"ready").unwrap();
            thread::sleep(Duration::from_secs(30));
        } else {
            panic!("unknown child lease mode");
        }
    }

    #[test]
    fn lease_is_exclusive_across_processes_and_released_without_unlink() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let lease = ConfigurationLease::acquire(first.path()).unwrap();
        probe(first.path(), false);
        probe(second.path(), true);
        drop(lease);
        assert!(first.path().join(LOCK_NAME).exists());
        probe(first.path(), true);
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn crashed_process_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_configuration::tests::child_lease_probe"])
            .env(MODE, "hold")
            .env(DIRECTORY, dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let ready = dir.path().join("child-ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "lease child exited early"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(ready.exists(), "lease child did not acquire the lock");
        assert!(ConfigurationLease::acquire(dir.path()).is_err());
        drop(child);
        assert!(ConfigurationLease::acquire(dir.path()).is_ok());
        assert!(dir.path().join(LOCK_NAME).exists());
    }

    #[test]
    fn rejects_junction_directory_and_reparse_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let junction = dir.path().join("junction");
        let output = Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "junction creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(ConfigurationLease::acquire(&junction).is_err());

        // File symlinks need Developer Mode or a privilege on some Windows hosts.
        let linked_lock = target.join(LOCK_NAME);
        let ordinary_file = dir.path().join("ordinary");
        fs::write(&ordinary_file, b"synthetic").unwrap();
        match symlink_file(&ordinary_file, &linked_lock) {
            Ok(()) => {
                println!("file-symlink rejection branch: executed");
                assert!(ConfigurationLease::acquire(&target).is_err());
            }
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                println!("file-symlink rejection branch: skipped (permission denied)");
            }
            Err(error) => panic!("file symlink creation failed: {error}"),
        }
    }
}
