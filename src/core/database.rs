use encrypted_storage;

use std::env;
use std::fs;
use std::path;
use std::vec::Vec;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/database";

// Next steps:
// 1. Documentation

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

    describe! determine_database_path {
        before_each {
            env::remove_var(ENVIRONMENT_KEY);
        }

        it "uses environment variable before hardcoded path" {
            env::set_var(ENVIRONMENT_KEY, "test_dir/env/ironvault");
            assert_eq!(determine_database_path(None), "test_dir/env/ironvault");
        }

        it "uses explicit path if one is provided" {
            assert_eq!(determine_database_path(Some("test_dir/explicit")),
                                   "test_dir/explicit");

            env::set_var(ENVIRONMENT_KEY, "test_dir/env/ironvault");

            assert_eq!(determine_database_path(Some("test_dir/explicit")),
                                   "test_dir/explicit");
        }

        it "uses the hardcoded path if no other form is available" {
            assert!(determine_database_path(None).ends_with("/.ironvault/database"));
        }
    }

    describe! resolve_database_path {
        before_each {
            env::remove_var(ENVIRONMENT_KEY);
            remove_test_dir();
        }

        after_each {
            remove_test_dir();
        }

        it "should create the directory if one doesn't exist" {
            env::set_var(ENVIRONMENT_KEY, "test_dir/something/ironvault");

            assert!(!path::Path::new("test_dir").is_dir());
            assert!(!path::Path::new("test_dir/something").is_dir());
            assert!(!path::Path::new("test_dir/something/ironvault").is_dir());

            resolve_database_path();

            assert!(path::Path::new("test_dir").is_dir());
            assert!(path::Path::new("test_dir/something").is_dir());
            assert!(!path::Path::new("test_dir/something/ironvault").is_dir());
        }
    }

    fn remove_test_dir() {
        fs::remove_dir_all("test_dir").unwrap_or(());
    }
}
