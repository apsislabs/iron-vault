use encrypted_storage;

use std::env;
use std::fs;
use std::path;
use std::vec::Vec;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/database";

pub struct Database {
    pub path: path::PathBuf,
    storage: encrypted_storage::EncryptedStorage,
}

impl Database {
    pub fn new(key: Vec<u8>) -> Database {
        let path = resolve_database_path();

        Database {
            path: path.clone(),
            storage: encrypted_storage::EncryptedStorage::new(path, key),
        }
    }

    pub fn read_string(&self, buffer: &mut String) {
        let mut sealed_buffer: Vec<u8> = Vec::new();

        let plaintext = self.read(&mut sealed_buffer);

        buffer.clear();
        buffer.push_str(&String::from_utf8_lossy(&plaintext));
    }

    pub fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a [u8] {
        return &self.storage
            .read(buffer)
            .expect("Should have read encrypted storage successfully.");
    }

    pub fn write(&self, buffer: &[u8]) {
        &self.storage
            .write(buffer)
            .expect("Should have written to encrypted storage successfully.");
    }
}

fn determine_database_path(path: Option<&str>) -> String {
    // 1 - Explicit Override Resolution
    if path.is_some() {
        return String::from(path.unwrap());
    }

    // 2 - Environment Variable Resolution
    let environment_result = env::var(ENVIRONMENT_KEY);
    if environment_result.is_ok() {
        return environment_result.unwrap();
    }

    // 3 - Hardcoded Resolution
    let home_dir = env::home_dir().expect("Failed to find the home directory");
    return format!("{}{}", home_dir.display(), DEFAULT_DATABASE_PATH);
}

fn resolve_database_path() -> path::PathBuf {
    let path = determine_database_path(None);

    let path = path::PathBuf::from(&path);

    match path.parent() {
        Some(parent) => {
            fs::create_dir_all(parent).expect("Failed to create the directory for the database")
        }
        _ => panic!("The path didn't have a parent attribute."),
    }

    return path;
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::remove_dir_all;
    use std::path::Path;

    #[test]
    fn determine_database_path_with_environment_variable() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "~/test_tmp/ironvault");
            assert_eq!(determine_database_path(None), "~/test_tmp/ironvault");
        });
    }

    #[test]
    fn determine_database_path_with_default_directory() {
        test_cleanup(&|| {
            assert!(determine_database_path(None).ends_with("/.ironvault/database"));
        });
    }

    #[test]
    fn determine_database_path_with_explicit_path() {
        test_cleanup(&|| {
            assert_eq!(determine_database_path(Some("~/.test_tmp/ironvault-explicit")),
                       "~/.test_tmp/ironvault-explicit");
        });
    }

    #[test]
    fn resolve_database_path_creates_a_directory() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "test_dir/something/ironvault");

            assert!(!Path::new("test_dir").is_dir());
            assert!(!Path::new("test_dir/something").is_dir());
            assert!(!Path::new("test_dir/something/ironvault").is_dir());

            let db_path = resolve_database_path();

            assert!(Path::new("test_dir").is_dir());
            assert!(Path::new("test_dir/something").is_dir());
            assert!(!Path::new("test_dir/something/ironvault").is_dir());
        });
    }

    fn test_cleanup(tests_fn: &Fn()) {
        perform_cleanup();
        tests_fn();
        perform_cleanup();
    }

    fn perform_cleanup() {
        remove_test_dir();
        env::remove_var(ENVIRONMENT_KEY);
    }

    fn remove_test_dir() {
        remove_dir_all("test_dir").unwrap_or(())
    }
}
