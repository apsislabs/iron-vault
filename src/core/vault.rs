use storage::Storage;
use storage::EncryptedStorage;
use storage::PlaintextStorage;
use storage;
use keys;
use record;

use std::io;
use std::env;
use std::error;
use std::fs;
use std::fmt;
use std::path;
use std::vec::Vec;
use std::collections::HashMap;
use ring::aead;
use ring::rand;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/";

#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration {
    salt: Vec<u8>,
}

pub struct Vault {
    pub path: path::PathBuf,
    // TODO (CONFIGURABLE): Use Configuration to change various parameters.
    _configuration: Configuration,
    record_storage: EncryptedStorage,
    _key_storage: EncryptedStorage,
    // TODO: UUIDSTRING
    records: HashMap<String, record::Record>
}

impl Vault {
    pub fn create(password: String, path: Option<&str>) -> Result<Vault, VaultError> {
        let random = rand::SystemRandom::new(); // TODO: Use a single random value
        let algorithm = &aead::CHACHA20_POLY1305;

        let path = create_vault_directory(path)?;

        // Generate and write the vault configuration
        let config = create_vault_configuration(&random)?;
        let config_storage = PlaintextStorage::new(config_path(&path));
        config_storage.write_object(&config)?;

        // Generate and write the encryption key
        let password_key = keys::derive_key(algorithm, &config.salt, password)?;
        let encryption_key_storage = EncryptedStorage::new(encrypted_key_path(&path), password_key);
        let encryption_key = keys::generate_key(algorithm, &random)?;
        encryption_key_storage.write(&encryption_key)?;

        // Generate and write the records
        let records = HashMap::new();
        let record_storage = EncryptedStorage::new(storage_path(&path), encryption_key.to_vec());
        record_storage.write_object(&records)?;

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
        let path = path::PathBuf::from(determine_vault_path(path)?);

        // Read the configuration
        let config_storage = PlaintextStorage::new(config_path(&path));
        let config: Configuration = config_storage.read_object()?;

        // Read the encryption_key
        let password_key = keys::derive_key(algorithm, &config.salt, password)?;
        let encryption_key_storage = EncryptedStorage::new(encrypted_key_path(&path), password_key);
        let mut buffer: Vec<u8> = Vec::new();
        let encryption_key = encryption_key_storage.read(&mut buffer)?;

        // Read the records
        let record_storage = EncryptedStorage::new(storage_path(&path), encryption_key.to_vec());
        let records = record_storage.read_object()?;

        return Ok(Vault {
            path: path,
            _configuration: config,
            record_storage: record_storage,
            _key_storage: encryption_key_storage,
            records: records,
        });
    }

    pub fn add_record(&mut self, record: record::Record) -> Result<(), VaultError> {
        self.records.insert(record.uuid.clone(), record);
        self.record_storage.write_object(&self.records)?;

        return Ok(());
    }

    pub fn fetch_records(&self) -> Vec<record::Record> {
        // Oh, my lord. The cloned() in here is probably problematic (eventually).
        return self.records.values().cloned().collect();
    }

    pub fn get_records_by_name(&self, record_name: String) -> Vec<&record::Record> {
        return self.records.values().filter(|record| record.name == record_name).collect();
    }

    pub fn get_record_by_uuid(&self, record_uuid: String) -> Option<&record::Record> {
        return self.records.get(&record_uuid);
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

fn determine_vault_path(path: Option<&str>) -> Result<String, VaultError> {
    // 1 - Explicit Override Resolution
    if path.is_some() {
        return Ok(String::from(path.unwrap()));
    }

    // 2 - Environment Variable Resolution
    let environment_result = env::var(ENVIRONMENT_KEY);
    if environment_result.is_ok() {
        return Ok(environment_result.unwrap());
    }

    // 3 - Hardcoded Resolution
    let home_dir = env::home_dir().ok_or(VaultError::UnknownError)?;
    return Ok(format!("{}{}", home_dir.display(), DEFAULT_DATABASE_PATH));
}

fn create_vault_directory(path: Option<&str>) -> Result<path::PathBuf, VaultError> {
    let path = determine_vault_path(path)?;
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
// TODO Errors are annoying as crap! Setup some kind of code generation for these.
pub enum VaultError {
    KeyError(keys::KeyError),
    ConfigurationFileError(io::Error),
    VaultStorageError(storage::StorageError),
    VaultAlreadyExists,
    VaultGenerationError,
    UnknownError
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VaultError::KeyError(ref err) => write!(f, "Salt error: {}", err),
            VaultError::ConfigurationFileError(ref err) => write!(f, "Configuration file error: {}", err),
            VaultError::VaultStorageError(ref err) => write!(f, "Storage error: {}", err),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists."),
            VaultError::VaultGenerationError => write!(f, "Vault generation error."),
            VaultError::UnknownError => write!(f, "An unknown error occured."),
        }
    }
}

impl error::Error for VaultError {
    fn description(&self) -> &str {
        match *self {
            VaultError::KeyError(ref err) => err.description(),
            VaultError::ConfigurationFileError(ref err) => err.description(),
            VaultError::VaultStorageError(ref err) => err.description(),
            VaultError::VaultAlreadyExists => "Vault already exists.",
            VaultError::VaultGenerationError => "Vault generation error.",
            VaultError::UnknownError => "An unknown error occured.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            VaultError::KeyError(ref err) => Some(err),
            VaultError::ConfigurationFileError(ref err) => Some(err),
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

impl From<storage::StorageError> for VaultError {
    fn from(err: storage::StorageError) -> VaultError {
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
            assert_eq!(determine_vault_path(None).unwrap(), "test_dir/env/ironvault");
        }

        it "uses explicit path if one is provided" {
            assert_eq!(determine_vault_path(Some("test_dir/explicit")).unwrap(),
                                   "test_dir/explicit");

            env::set_var(ENVIRONMENT_KEY, "test_dir/env/ironvault");

            assert_eq!(determine_vault_path(Some("test_dir/explicit")).unwrap(),
                                   "test_dir/explicit");
        }

        it "uses the hardcoded path if no other form is available" {
            assert!(determine_vault_path(None).unwrap().ends_with("/.ironvault/"));
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
