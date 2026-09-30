//! macOS-only default-ACL creation and exclusive local configuration lifetime.
use std::{
    fs::{File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
};

pub(crate) struct ConfigurationLease {
    _file: File,
}

impl ConfigurationLease {
    pub(crate) fn acquire(directory: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(directory).map_err(|_| "无法建立本机配置目录")?;
        if directory
            .canonicalize()
            .map_err(|_| "无法核对本机配置目录")?
            != directory
        {
            return Err("本机配置目录不能经过符号链接".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("credential-session.lock"))
            .map_err(|_| "无法建立本机配置锁")?;
        let info = file.metadata().map_err(|_| "无法核对本机配置锁")?;
        if !info.is_file()
            || info.nlink() != 1
            || info.uid() != unsafe { libc::geteuid() }
            || info.mode() & 0o077 != 0
        {
            return Err("本机配置锁的权限或文件类型无效".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("另一个本机客户端正在运行，请先正常退出后重试".into());
        }
        // Never unlink the lock: a second inode would allow two writers.
        Ok(Self { _file: file })
    }
}

#[cfg(not(test))]
pub(crate) struct NativeMigration;

#[cfg(not(test))]
impl crate::credential_migration::MigrationBackend for NativeMigration {
    fn current(
        &self,
        id: &str,
        kind: &str,
    ) -> Result<zeroize::Zeroizing<String>, crate::secret_store::SecretError> {
        read("org.shortlink.generator.credentials.v2", id, kind)
    }
    fn legacy(
        &self,
        id: &str,
        kind: &str,
    ) -> Result<zeroize::Zeroizing<String>, crate::secret_store::SecretError> {
        read("org.shortlink.generator", id, kind)
    }
    fn create(
        &self,
        id: &str,
        kind: &str,
        value: &str,
    ) -> Result<crate::credential_migration::Created, crate::secret_store::SecretError> {
        use crate::{credential_migration::Created, secret_store::SecretError};
        use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
        if !crate::credential_migration::KINDS.contains(&kind) {
            return Err(SecretError::Other);
        }
        let keychain =
            SecKeychain::default_for_domain(SecPreferencesDomain::User).map_err(native_error)?;
        match keychain.add_generic_password(
            "org.shortlink.generator.credentials.v2",
            &format!("{kind}:{id}"),
            value.as_bytes(),
        ) {
            Ok(()) => Ok(Created::New),
            Err(error) if error.code() == -25299 => Ok(Created::AlreadyExists),
            Err(error) => Err(native_error(error)),
        }
    }
}

#[cfg(not(test))]
fn native_error(error: security_framework::base::Error) -> crate::secret_store::SecretError {
    use crate::secret_store::SecretError;
    match error.code() {
        -25300 => SecretError::Missing,
        -25293 | -25308 | -128 => SecretError::AccessDenied,
        _ => SecretError::Unavailable,
    }
}

#[cfg(not(test))]
fn read(
    service: &str,
    id: &str,
    kind: &str,
) -> Result<zeroize::Zeroizing<String>, crate::secret_store::SecretError> {
    use crate::secret_store::SecretError;
    if !crate::credential_migration::KINDS.contains(&kind) {
        return Err(SecretError::Other);
    }
    let entry =
        keyring::Entry::new(service, &format!("{kind}:{id}")).map_err(|_| SecretError::Other)?;
    entry
        .get_password()
        .map(zeroize::Zeroizing::new)
        .map_err(|error| match error {
            keyring::Error::NoEntry => SecretError::Missing,
            keyring::Error::NoStorageAccess(_) => SecretError::AccessDenied,
            keyring::Error::PlatformFailure(_) => SecretError::Unavailable,
            _ => SecretError::Other,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_is_exclusive_and_released_without_removing_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().canonicalize().unwrap();
        let first = ConfigurationLease::acquire(&directory).unwrap();
        assert!(ConfigurationLease::acquire(&directory).is_err());
        drop(first);
        assert!(dir.path().join("credential-session.lock").exists());
        assert!(ConfigurationLease::acquire(&directory).is_ok());
    }
    #[test]
    fn lease_rejects_symlink_or_public_file() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().canonicalize().unwrap();
        let target = dir.path().join("other");
        std::fs::write(&target, "synthetic").unwrap();
        let path = dir.path().join("credential-session.lock");
        symlink(&target, &path).unwrap();
        assert!(ConfigurationLease::acquire(&directory).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ConfigurationLease::acquire(&directory).is_err());
    }
}
