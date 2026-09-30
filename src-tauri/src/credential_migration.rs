//! Explicit, create-only migration. This module never caches or changes cloud state.
use crate::secret_store::SecretError;
use zeroize::Zeroizing;

pub(crate) const KINDS: [&str; 4] = ["token", "selftest", "probe", "selftest-pending"];

pub(crate) enum Created {
    New,
    AlreadyExists,
}

pub(crate) trait MigrationBackend {
    fn current(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError>;
    fn legacy(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError>;
    fn create(&self, id: &str, kind: &str, value: &str) -> Result<Created, SecretError>;
}

/// Called only after the account's one-use migration plan has been acknowledged.
/// A completed account may contain genuinely absent optional credentials.
pub(crate) fn migrate(backend: &impl MigrationBackend, id: &str) -> Result<(), SecretError> {
    for kind in KINDS {
        match backend.current(id, kind) {
            Ok(_) => continue,
            Err(SecretError::Missing) => {}
            Err(error) => return Err(error),
        }
        let old = match backend.legacy(id, kind) {
            Ok(value) => value,
            Err(SecretError::Missing) if kind != "token" => continue,
            Err(SecretError::Missing) => return Err(SecretError::LegacyTokenMissing),
            Err(error) => return Err(error),
        };
        let created = backend.create(id, kind, &old)?;
        // Never trust set/get cache success, including the duplicate-item race.
        let actual = backend.current(id, kind)?;
        if actual.as_bytes() != old.as_bytes() {
            return Err(match created {
                Created::New => SecretError::ReadbackMismatch,
                Created::AlreadyExists => SecretError::Conflict,
            });
        }
    }
    Ok(())
}

/// Native deletion wrappers can discard the platform deletion status. Only an
/// uncached, exact current-namespace Missing result proves the postcondition.
pub(crate) fn remove_current_verified(
    mut remove: impl FnMut(&str) -> Result<(), SecretError>,
    mut current: impl FnMut(&str) -> Result<Zeroizing<String>, SecretError>,
) -> Result<(), SecretError> {
    for kind in KINDS {
        remove(kind)?;
        match current(kind) {
            Err(SecretError::Missing) => {}
            Ok(_) => return Err(SecretError::DeletionNotConfirmed),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};

    #[test]
    fn deletion_requires_direct_absence_and_stops_on_retained_denied_or_failed_readback() {
        for result in [
            Ok(Zeroizing::new("synthetic-retained".to_owned())),
            Err(SecretError::AccessDenied),
            Err(SecretError::Unavailable),
            Err(SecretError::Other),
        ] {
            let deletes = RefCell::new(Vec::new());
            let reads = RefCell::new(Vec::new());
            let checked = remove_current_verified(
                |kind| {
                    deletes.borrow_mut().push(kind.to_owned());
                    Ok(())
                },
                |kind| {
                    reads.borrow_mut().push(kind.to_owned());
                    result.clone()
                },
            );
            assert!(checked.is_err());
            assert_eq!(*deletes.borrow(), vec!["token"]);
            assert_eq!(*reads.borrow(), vec!["token"]);
        }
        let calls = RefCell::new(Vec::new());
        assert!(remove_current_verified(
            |kind| {
                calls.borrow_mut().push(format!("delete:{kind}"));
                Ok(())
            },
            |kind| {
                calls.borrow_mut().push(format!("read:{kind}"));
                Err(SecretError::Missing)
            }
        )
        .is_ok());
        assert_eq!(
            calls.into_inner(),
            KINDS
                .iter()
                .flat_map(|kind| [format!("delete:{kind}"), format!("read:{kind}")])
                .collect::<Vec<_>>()
        );
    }

    #[derive(Default)]
    struct Mock {
        current: RefCell<HashMap<String, String>>,
        old: HashMap<String, String>,
        calls: RefCell<Vec<String>>,
        read_error: Option<SecretError>,
        fail_kind: Option<&'static str>,
        duplicate: Option<&'static str>,
        bad_readback: bool,
    }
    impl MigrationBackend for Mock {
        fn current(&self, _: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            self.calls.borrow_mut().push(format!("current:{kind}"));
            if let Some(error) = self.read_error {
                return Err(error);
            }
            self.current
                .borrow()
                .get(kind)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(SecretError::Missing)
        }
        fn legacy(&self, _: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            self.calls.borrow_mut().push(format!("legacy:{kind}"));
            if self.fail_kind == Some(kind) {
                return Err(SecretError::AccessDenied);
            }
            self.old
                .get(kind)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(SecretError::Missing)
        }
        fn create(&self, _: &str, kind: &str, value: &str) -> Result<Created, SecretError> {
            self.calls.borrow_mut().push(format!("create:{kind}"));
            let replacement =
                self.duplicate
                    .unwrap_or(if self.bad_readback { "wrong" } else { value });
            self.current
                .borrow_mut()
                .insert(kind.into(), replacement.into());
            Ok(if self.duplicate.is_some() {
                Created::AlreadyExists
            } else {
                Created::New
            })
        }
    }
    fn fixture() -> Mock {
        Mock {
            old: KINDS
                .iter()
                .map(|k| (k.to_string(), format!("synthetic-{k}")))
                .collect(),
            ..Default::default()
        }
    }
    #[test]
    fn all_kinds_are_copied_and_directly_read_back_without_changing_legacy() {
        let backend = fixture();
        let before = backend.old.clone();
        assert!(migrate(&backend, "one").is_ok());
        assert_eq!(*backend.current.borrow(), before);
        assert_eq!(backend.old, before);
        for kind in KINDS {
            assert_eq!(
                backend
                    .calls
                    .borrow()
                    .iter()
                    .filter(|x| *x == &format!("current:{kind}"))
                    .count(),
                2
            );
        }
        backend.calls.borrow_mut().clear();
        assert!(migrate(&backend, "one").is_ok());
        assert!(backend
            .calls
            .borrow()
            .iter()
            .all(|x| x.starts_with("current:")));
    }
    #[test]
    fn current_denial_never_falls_back_or_creates() {
        for error in [
            SecretError::AccessDenied,
            SecretError::Unavailable,
            SecretError::Other,
        ] {
            let backend = Mock {
                read_error: Some(error),
                ..fixture()
            };
            assert!(matches!(migrate(&backend,"one"),Err(e) if e==error));
            assert_eq!(*backend.calls.borrow(), vec!["current:token"]);
        }
    }
    #[test]
    fn cancelled_partial_migration_stops_and_resumes_from_existing_current_values() {
        for (index, kind) in KINDS.iter().enumerate() {
            let mut backend = Mock {
                fail_kind: Some(kind),
                ..fixture()
            };
            assert!(matches!(
                migrate(&backend, "one"),
                Err(SecretError::AccessDenied)
            ));
            assert_eq!(backend.current.borrow().len(), index);
            assert!(!backend
                .calls
                .borrow()
                .iter()
                .any(|x| x == &format!("create:{kind}")));
            backend.fail_kind = None;
            backend.calls.borrow_mut().clear();
            assert!(migrate(&backend, "one").is_ok());
            for previous in KINDS.iter().take(index) {
                assert!(!backend
                    .calls
                    .borrow()
                    .contains(&format!("legacy:{previous}")));
            }
        }
    }
    #[test]
    fn duplicate_races_compare_without_overwriting() {
        let backend = Mock {
            old: HashMap::from([("token".into(), "same".into())]),
            duplicate: Some("same"),
            ..Default::default()
        };
        assert!(migrate(&backend, "one").is_ok());
        let backend = Mock {
            duplicate: Some("newer-current"),
            ..fixture()
        };
        assert!(matches!(
            migrate(&backend, "one"),
            Err(SecretError::Conflict)
        ));
        assert_eq!(
            backend.current.borrow().get("token").unwrap(),
            "newer-current"
        );
        assert_eq!(backend.current.borrow().len(), 1);
    }
    #[test]
    fn direct_readback_mismatch_does_not_complete() {
        let backend = Mock {
            bad_readback: true,
            ..fixture()
        };
        assert!(matches!(
            migrate(&backend, "one"),
            Err(SecretError::ReadbackMismatch)
        ));
        assert_eq!(backend.current.borrow().len(), 1);
    }
    #[test]
    fn optional_absence_is_allowed_but_token_absence_is_not() {
        let mut backend = Mock::default();
        assert!(matches!(
            migrate(&backend, "one"),
            Err(SecretError::LegacyTokenMissing)
        ));
        backend.old.insert("token".into(), "synthetic".into());
        assert!(migrate(&backend, "one").is_ok());
        assert_eq!(backend.current.borrow().len(), 1);
    }
}
