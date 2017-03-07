use encrypted_storage::EncryptedStorage;
use encrypted_storage;
use keys;
use record;

use std::io::prelude::*;
use std::io;
use std::env;
use std::error;
use std::fs;
use std::fmt;
use std::path;
use std::vec::Vec;
use ring::aead;
use ring::rand;
use serde_json;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/";

#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration {
    salt: Vec<u8>,
}

impl Configuration {
    pub fn to_json(&self) -> Result<String, VaultError> {
        return serde_json::to_string(self).map_err(VaultError::ConfigurationSerializationError);
    }

    pub fn from_json(json: String) -> Result<Configuration, VaultError> {
        return serde_json::from_str(&json).map_err(VaultError::ConfigurationSerializationError);
    }

    pub fn save_to<P: AsRef<path::Path>>(&self, path: P) -> Result<(), VaultError> {
        let mut file = fs::File::create(path)?;
        let json = self.to_json()?;

        file.write_all(json.as_bytes())?;

        return Ok(());
    }

    pub fn from_file<P: AsRef<path::Path>>(path: P) -> Result<Configuration, VaultError> {
        let mut file = fs::File::open(path)?;
        let mut json = String::new();
        file.read_to_string(&mut json)?;

        return Configuration::from_json(json);
    }
}

pub struct Vault {
    pub path: path::PathBuf,
    // TODO (CONFIGURABLE): Use Configuration to change various parameters.
    _configuration: Configuration,
    record_storage: EncryptedStorage,
    _key_storage: EncryptedStorage,
    records: Vec<record::Record>
}

impl Vault {
    pub fn create(password: String, path: Option<&str>) -> Result<Vault, VaultError> {
        let random = rand::SystemRandom::new(); // TODO: Use a single random value
        let algorithm = &aead::CHACHA20_POLY1305;

        // Fail if the directory exists
        let path = create_vault_directory(path)?;

        // Write the vault configuration
        let config = create_vault_configuration(&random)?;
        config.save_to(config_path(&path))?;

        let password_key = keys::derive_key(algorithm, &config.salt, password)?;
        let encryption_key_storage = EncryptedStorage::new(encrypted_key_path(&path), password_key);
        let encryption_key = keys::generate_key(algorithm, &random)?;
        encryption_key_storage.write(&encryption_key)?;

        let records = Vec::new();
        let record_storage = EncryptedStorage::new(storage_path(&path), encryption_key.to_vec());
        let json = serde_json::to_string(&records)?;
        record_storage.write(json.as_bytes())?;

        return Ok(Vault {
            path: path,
            _configuration: config,
            record_storage: record_storage,
            _key_storage: encryption_key_storage,
            records: records,
        });
    }

    pub fn open(password: String, path: Option<&str>) -> Result<Vault, VaultError> {
        let algorithm = &aead::CHACHA20_POLY1305;

        let path = path::PathBuf::from(determine_vault_path(path));

        let config = Configuration::from_file(config_path(&path))?;

        let password_key = keys::derive_key(algorithm, &config.salt, password)?;
        let encryption_key_storage = EncryptedStorage::new(encrypted_key_path(&path), password_key);
        let mut sealed_buffer: Vec<u8> = Vec::new();
        let encryption_key = encryption_key_storage.read(&mut sealed_buffer).expect("Should have opened DB correctly");

        let record_storage = EncryptedStorage::new(storage_path(&path), encryption_key.to_vec());
        let record_json = record_storage.read_string().expect("Should have read the json");
        let records = serde_json::from_str(&record_json).expect("Should have deserialized from the json");

        return Ok(Vault {
            path: path,
            _configuration: config,
            record_storage: record_storage,
            _key_storage: encryption_key_storage,
            records: records,
        });
    }

    pub fn add_record(&mut self, record: record::Record) {
        self.records.push(record);

        // Write new record
        let json = serde_json::to_string(&self.records).unwrap();
        &self.record_storage.write_string(&json).expect("Should have written record_storage properly");
    }

    pub fn fetch_records(&self) -> &Vec<record::Record> {
        return &self.records;
    }

    pub fn get_records_by_name(&self, record_name: String) -> Vec<&record::Record> {
        return self.records.iter().filter(|record| record.name == record_name).collect();
    }

    pub fn get_record_by_uuid(&self, record_uuid: String) -> Option<&record::Record> {
        return self.records.iter().find(|record| record.uuid == record_uuid);
    }
}

fn encrypted_key_path(path: &path::PathBuf) -> path::PathBuf {
    return vault_path(path, "key".to_string());
}

fn storage_path(path: &path::PathBuf) -> path::PathBuf {
    return vault_path(path, "storage".to_string());
}

fn config_path(path: &path::PathBuf) -> path::PathBuf {
    return vault_path(path, "config".to_string());
}

fn vault_path(base_path: &path::PathBuf, path: String) -> path::PathBuf {
    let mut vault_path = base_path.clone();
    vault_path.push(path);
    return vault_path;
}

// TODO: rename determine_vault_path
// TODO: error handling
fn determine_vault_path(path: Option<&str>) -> String {
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

fn create_vault_directory(path: Option<&str>) -> Result<path::PathBuf, VaultError> {
    let path = determine_vault_path(path);
    let path = path::PathBuf::from(&path);

    if path.exists() { return Err(VaultError::VaultAlreadyExists); }
    try!(fs::create_dir_all(&path).map_err(|_| VaultError::VaultGenerationError));

    Ok(path)
}

fn create_vault_configuration(random: &rand::SystemRandom) -> Result<Configuration, VaultError> {
    let salt = try!(keys::generate_salt(random));

    return Ok(Configuration {
        salt: salt
    });
}

#[derive(Debug)]
// TODO Code Generation for these errors
pub enum VaultError {
    KeyError(keys::KeyError),
    ConfigurationSerializationError(serde_json::Error),
    ConfigurationFileError(io::Error),
    VaultStorageError(encrypted_storage::StorageError),
    VaultAlreadyExists,
    VaultGenerationError
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VaultError::KeyError(ref err) => write!(f, "Salt error: {}", err),
            VaultError::ConfigurationSerializationError(ref err) => write!(f, "Configuration serialization error: {}", err),
            VaultError::ConfigurationFileError(ref err) => write!(f, "Configuration file error: {}", err),
            VaultError::VaultStorageError(ref err) => write!(f, "Storage error: {}", err),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists."),
            VaultError::VaultGenerationError => write!(f, "Vault generation error."),
        }
    }
}

impl error::Error for VaultError {
    fn description(&self) -> &str {
        match *self {
            VaultError::KeyError(ref err) => err.description(),
            VaultError::ConfigurationSerializationError(ref err) => err.description(),
            VaultError::ConfigurationFileError(ref err) => err.description(),
            VaultError::VaultStorageError(ref err) => err.description(),
            VaultError::VaultAlreadyExists => "Vault already exists.",
            VaultError::VaultGenerationError => "Vault generation error.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            VaultError::KeyError(ref err) => Some(err),
            VaultError::ConfigurationFileError(ref err) => Some(err),
            VaultError::ConfigurationSerializationError(ref err) => Some(err),
            VaultError::VaultStorageError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<keys::KeyError> for VaultError {
    fn from(err: keys::KeyError) -> VaultError {
        VaultError::KeyError(err)
    }
}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> VaultError {
        VaultError::ConfigurationFileError(err)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(err: serde_json::Error) -> VaultError {
        VaultError::ConfigurationSerializationError(err)
    }
}

impl From<encrypted_storage::StorageError> for VaultError {
    fn from(err: encrypted_storage::StorageError) -> VaultError {
        VaultError::VaultStorageError(err)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    describe! determine_vault_path {
        before_each {
            env::remove_var(ENVIRONMENT_KEY);
        }

        it "uses environment variable before hardcoded path" {
            env::set_var(ENVIRONMENT_KEY, "test_dir/env/ironvault");
            assert_eq!(determine_vault_path(None), "test_dir/env/ironvault");
        }

        it "uses explicit path if one is provided" {
            assert_eq!(determine_vault_path(Some("test_dir/explicit")),
                                   "test_dir/explicit");

            env::set_var(ENVIRONMENT_KEY, "test_dir/env/ironvault");

            assert_eq!(determine_vault_path(Some("test_dir/explicit")),
                                   "test_dir/explicit");
        }

        it "uses the hardcoded path if no other form is available" {
            assert!(determine_vault_path(None).ends_with("/.ironvault/"));
        }
    }

    describe! create_vault_directory {
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

            create_vault_directory(None).unwrap();

            assert!(path::Path::new("test_dir").is_dir());
            assert!(path::Path::new("test_dir/something").is_dir());
            assert!(path::Path::new("test_dir/something/ironvault").is_dir());
        }
    }

    fn remove_test_dir() {
        fs::remove_dir_all("test_dir").unwrap_or(());
    }
}
