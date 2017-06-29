use std::io::prelude::*;
use std::io;
use std::error;
use std::fmt;
use std::fs;
use std::path;
use std::string;
use std::vec::Vec;
use ring::aead;
use ring::rand;
use ring::rand::SecureRandom;
use serde;
use serde_json;

/// The `Storage` trait allows for reading and writing objects to a long-term storage format.
pub trait Storage {
    /// Reads data from the file represented by this Storage.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8], StorageError>;

    /// Read a string from the file represented by this Storage.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    /// * `StorageError::StringError` if the file contents cannot be interpreted as a UTF-8 string.
    fn read_string(&self) -> Result<String, StorageError> {
        let mut sealed_buffer: Vec<u8> = Vec::new();

        let plaintext = self.read(&mut sealed_buffer)?;
        return Ok(String::from_utf8(plaintext.to_vec())?);
    }

    /// Read a Serializable object from the file represented by this Storage. The data in the file
    /// should be a JSON serialized version of the object.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    /// * `StorageError::StringError` if the file contents cannot be interpreted as a UTF-8 string.
    /// * `StorageError::SerializationError` if the file contents cannot be interpreted as a json
    /// representation of the desired type.
    fn read_object<T>(&self) -> Result<T, StorageError>
        where T: serde::Deserialize
    {
        let json = self.read_string()?;

        let object = serde_json::from_str(&json)?;

        return Ok(object);
    }

    /// Writes the given data to file represented by this Storage.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    fn write(&self, buffer: &[u8]) -> Result<(), StorageError>;

    /// Writes the given string to the file represented by this Storage.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    fn write_string(&self, data: &String) -> Result<(), StorageError> {
        return self.write(data.as_bytes());
    }

    /// Writes a Serializable object to the file represented by this Storage.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason (i.e. it doesn't
    /// exist, or the process doesn't have permission to open it.)
    /// * `StorageError::SerializationError` if the given object fails during Serialization.
    fn write_object<T: ?Sized>(&self, object: &T) -> Result<(), StorageError>
        where T: serde::Serialize
    {
        let json = serde_json::to_string(object)?;
        return self.write_string(&json);
    }
}

/// A reference to a plaintext file.
///
/// An instance of `PlaintextStorage` can read or write bytes to the path it was initialized with.
/// These files are written in plaintext.
pub struct PlaintextStorage {
    path: path::PathBuf
}

impl PlaintextStorage {
    /// Creates a new `PlaintextStorage` with the given path.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::path::PathBuf;
    /// use vault_core::storage::PlaintextStorage;
    ///
    /// let path = PathBuf::from("test/plaintext");
    /// PlaintextStorage::new(path);
    /// ```
    pub fn new(path: path::PathBuf) -> PlaintextStorage {
        PlaintextStorage {
            path: path,
        }
    }
}

impl Storage for PlaintextStorage {
    fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8], StorageError> {
        return read_plaintext(&self.path, buffer);
    }

    fn write(&self, buffer: &[u8]) -> Result<(), StorageError> {
        return write_plaintext(&self.path, buffer);
    }
}

/// A reference to an encrypted file.
///
/// An instance of `EncryptedStorage` can read or write bytes to the path it was initialized with.
/// These files are written encrypted with the algorithm and key that are provided to `::new`.
pub struct EncryptedStorage {
    path: path::PathBuf,
    key: Vec<u8>,
    algorithm: &'static aead::Algorithm,
}

impl EncryptedStorage {
    /// Creates a new `EncryptedStorage` with the given key and path. The key should be a valid
    /// CHACHA20_POLY1305 key (256 bits long or 32 bytes long).
    ///
    /// # Examples
    /// ```rust,no_run
    /// use std::path::PathBuf;
    /// use vault_core::storage::EncryptedStorage;
    ///
    /// let path         = PathBuf::from("test/database");
    /// let key: Vec<u8> = b"7b6300f7dc21c9fddeaa71f439d53b55".to_vec();
    /// EncryptedStorage::new(path, key);
    /// ```
    pub fn new(path: path::PathBuf, key: Vec<u8>) -> EncryptedStorage {
        // CONFIGURABLE
        EncryptedStorage {
            path: path,
            key: key,
            algorithm: &aead::CHACHA20_POLY1305,
        }
    }
}

impl Storage for EncryptedStorage {
    /// Reads data from the encrypted storage using the CHACHA20_POLY1305 algorithm and the key for
    /// the current storage file.
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason
    /// (i.e. it doesn't exist, or the process doesn't have permission to open it.)
    /// * `StorageError::KeyLengthError` if the key is not the proper length
    /// for the CHACHA20_POLY1305 algorithm.
    /// * `StorageError::KeyError` if there is some other issue that occurs
    /// in generating the interal OpeningKey.
    /// * `StorageError::DecryptionError` if there is a problem decrypting the
    /// contents of the file (i.e. the file is not long enough to read the nonce, or the key does not
    /// decrypt the file properly).
    fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8], StorageError> {
        return read_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }

    /// Writes the given data to the encrypted storage using the CHACHA20_POLY1305 algorithm and the key for
    /// the current storage file. This will generate a new nonce using the system provided secure
    /// random generator (using `ring`).
    ///
    /// # Errors
    /// * `StorageError::FileError` if the file cannot be opened for any reason
    /// (i.e. it doesn't exist, or the process doesn't have permission to open it.)
    /// * `StorageError::KeyLengthError` if the key is not the proper length
    /// for the CHACHA20_POLY1305 algorithm.
    /// * `StorageError::KeyError` if there is some other issue that occurs
    /// in generating the interal OpeningKey.
    /// * `NonceGenerationError` if the nonce cannot be generated for any reason.
    /// * `StorageError::EncryptionError` if there is a problem decrypting the
    /// contents of the file (i.e. the file is not long enough to read the nonce, or the key does not
    /// decrypt the file properly).
    fn write(&self, buffer: &[u8]) -> Result<(), StorageError> {
        return write_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }
}

#[derive(Debug)]
pub enum StorageError {
    KeyLengthError,
    KeyError,
    NonceGenerationError,
    DecryptionError,
    EncryptionError,
    StringError(string::FromUtf8Error),
    FileError(io::Error),
    SerializationError(serde_json::Error),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StorageError::KeyLengthError => {
                write!(f,
                       "The key was not the right length for the encryption algorithm")
            }
            StorageError::KeyError => {
                write!(f,
                       "There was a problem with the key to access the encrypted storage.")
            }
            StorageError::NonceGenerationError => {
                write!(f, "There was a problem generating the nonce.")
            }
            StorageError::DecryptionError => {
                write!(f, "The encrypted data could not be decrypted.")
            }
            StorageError::EncryptionError => {
                write!(f, "The plaintext data could not be encrypted.")
            }
            StorageError::FileError(ref err) => {
                write!(f, "There was an error accessing the file: {}", err)
            }
            StorageError::StringError(ref err) => {
                write!(f, "There was an error processing the file: {}", err)
            }
            StorageError::SerializationError(ref err) => {
                write!(f, "There was an error processing the file: {}", err)
            }
        }
    }
}

impl error::Error for StorageError {
    fn description(&self) -> &str {
        match *self {
            StorageError::KeyLengthError => {
                "The key was not the right length for the encryption algorithm"
            }
            StorageError::KeyError => {
                "There was a problem with the key to access the encrypted storage."
            }
            StorageError::NonceGenerationError => "There was a problem geenrating the nonce.",
            StorageError::DecryptionError => "The encrypted data could not be decrypted.",
            StorageError::EncryptionError => "The plaintext data could not be encrypted.",
            StorageError::FileError(ref err) => err.description(),
            StorageError::StringError(ref err) => err.description(),
            StorageError::SerializationError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StorageError::KeyLengthError => None,
            StorageError::KeyError => None,
            StorageError::NonceGenerationError => None,
            StorageError::DecryptionError => None,
            StorageError::EncryptionError => None,
            StorageError::FileError(ref err) => Some(err),
            StorageError::StringError(ref err) => Some(err),
            StorageError::SerializationError(ref err) => Some(err),
        }
    }
}

impl From<string::FromUtf8Error> for StorageError {
    fn from(err: string::FromUtf8Error) -> StorageError {
        StorageError::StringError(err)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> StorageError {
        StorageError::SerializationError(err)
    }
}

fn read_plaintext<'a, P: AsRef<path::Path>>(path: P,
                                            buffer: &'a mut Vec<u8>)
                                            -> Result<&'a [u8], StorageError> {
    let mut f = try!(fs::File::open(path).map_err(StorageError::FileError));
    buffer.clear();

    f.read_to_end(buffer).map_err(StorageError::FileError)?;

    return Ok(buffer);
}

fn read_encrypted<'a, P: AsRef<path::Path>>(path: P,
                                            buffer: &'a mut Vec<u8>,
                                            key: &[u8],
                                            algorithm: &'static aead::Algorithm)
                                            -> Result<&'a [u8], StorageError> {
    read_plaintext(path, buffer)?;

    return open_data(buffer, key, algorithm);
}

fn write_plaintext<P: AsRef<path::Path>>(path: P,
                                         buf: &[u8])
                                         -> Result<(), StorageError> {

    let mut f = try!(fs::File::create(path).map_err(StorageError::FileError));

    try!(f.write_all(buf).map_err(StorageError::FileError));

    return Ok(());
}

fn write_encrypted<P: AsRef<path::Path>>(path: P,
                                         buf: &[u8],
                                         key: &[u8],
                                         algorithm: &'static aead::Algorithm)
                                         -> Result<(), StorageError> {
    let mut data = buf.to_vec();

    let ciphertext = try!(seal_data(&mut data, key, algorithm));
    try!(write_plaintext(path, ciphertext));

    return Ok(());
}

fn open_data<'a>(data: &'a mut Vec<u8>,
                 key: &[u8],
                 algorithm: &'static aead::Algorithm)
                 -> Result<&'a [u8], StorageError> {

    let nonce_len = algorithm.nonce_len();

    try!(verify_key_len(algorithm, key));

    let opening_key = try!(aead::OpeningKey::new(algorithm, &key)
        .map_err(|_| StorageError::KeyError));
    let nonce = data[..nonce_len].to_vec();

    let plaintext = try!(aead::open_in_place(&opening_key,
                                             &nonce,
                                             &empty_associated_data(),
                                             nonce_len,
                                             &mut data[..])
        .map_err(|_| StorageError::DecryptionError));

    return Ok(plaintext);
}

fn seal_data<'a>(data: &'a mut Vec<u8>,
                 key: &[u8],
                 algorithm: &'static aead::Algorithm)
                 -> Result<&'a [u8], StorageError> {

    let nonce_len = algorithm.nonce_len();
    let tag_len = algorithm.tag_len();

    try!(verify_key_len(algorithm, key));

    let sealing_key = try!(aead::SealingKey::new(algorithm, &key)
        .map_err(|_| StorageError::KeyError));
    let nonce = try!(generate_nonce(algorithm));

    append_tag_storage(data, algorithm);

    let ciphertext_len = try!(aead::seal_in_place(&sealing_key,
                                                  &nonce,
                                                  &empty_associated_data(),
                                                  &mut data[..],
                                                  tag_len)
        .map_err(|_| StorageError::EncryptionError));

    data.splice(..0, nonce);
    let encrypted_len = nonce_len + ciphertext_len;

    return Ok(&data[..encrypted_len]);
}

fn verify_key_len(algorithm: &'static aead::Algorithm, key: &[u8]) -> Result<(), StorageError> {
    if algorithm.key_len() != key.len() {
        return Err(StorageError::KeyLengthError);
    }

    return Ok(());
}

fn generate_nonce(algorithm: &'static aead::Algorithm) -> Result<Vec<u8>, StorageError> {
    let nonce_len = algorithm.nonce_len();
    let rng = rand::SystemRandom::new();

    let mut nonce: Vec<u8> = vec![0; nonce_len];
    try!(rng.fill(&mut nonce).map_err(|_| StorageError::NonceGenerationError));

    return Ok(nonce);
}

fn empty_associated_data() -> [u8; 0] {
    return [0; 0];
}

fn append_tag_storage(plaintext: &mut Vec<u8>, algorithm: &'static aead::Algorithm) {
    let tag_len = algorithm.tag_len();

    for _ in 0..tag_len {
        plaintext.push(0);
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct TestStruct {
        a: String,
        b: String,
        c: String,
    }

    describe! new {
        before_each {
            ensure_test_dir();
        }

        it "should instantiate without an error" {
            let key: &[u8] = b"7b6300f7dc21c9fddeaa71f439d53b55";
            EncryptedStorage::new(path::PathBuf::from("test_dir/database"), key.to_vec());
        }
    }

    describe! read_and_write_object {
        before_each {
            ensure_test_dir();
            let key: &[u8] = b"7b6300f7dc21c9fddeaa71f439d53b55";
            let _encrypted_storage = EncryptedStorage::new(path::PathBuf::from("test_dir/database"), key.to_vec());
            let _plaintext_storage = PlaintextStorage::new(path::PathBuf::from("test_dir/plaintext"));

            let _short_message = TestStruct {
                a: "Short message".to_string(),
                b: "Another message".to_string(),
                c: "Very cool message".to_string(),
            };
        }

        after_each {
            remove_test_dir();
        }

        it "should be able to read and write the Test Struct (plaintext)" {
            _plaintext_storage.write_object(&_short_message).unwrap();
            let deserialized:TestStruct = _plaintext_storage.read_object().unwrap();

            assert_eq!(deserialized.a, "Short message");
            assert_eq!(deserialized.b, "Another message");
            assert_eq!(deserialized.c, "Very cool message");
        }

        it "should be able to read and write the Test Struct (encrypted)" {
            _encrypted_storage.write_object(&_short_message).unwrap();
            let deserialized:TestStruct = _encrypted_storage.read_object().unwrap();

            assert_eq!(deserialized.a, "Short message");
            assert_eq!(deserialized.b, "Another message");
            assert_eq!(deserialized.c, "Very cool message");
        }

    }

    describe! write_and_read {
        before_each {
            ensure_test_dir();
            let key: &[u8] = b"7b6300f7dc21c9fddeaa71f439d53b55";
            let _encrypted_storage = EncryptedStorage::new(path::PathBuf::from("test_dir/database"), key.to_vec());
            let _plaintext_storage = PlaintextStorage::new(path::PathBuf::from("test_dir/plaintext"));
            let _short_message = String::from("Short message");
        }

        after_each {
            remove_test_dir();
        }

        it "should write to a file (encrypted)" {
            assert_eq!(path::Path::new("test_dir/database").is_file(), false);
            _encrypted_storage.write(_short_message.as_bytes()).expect("The write should be successful");
            assert!(path::Path::new("test_dir/database").is_file());
        }

        it "should write to file (plaintext)" {
            assert_eq!(path::Path::new("test_dir/plaintext").is_file(), false);
            _plaintext_storage.write(_short_message.as_bytes()).expect("The write should be successful");
            assert!(path::Path::new("test_dir/plaintext").is_file());
        }

        it "should write encrypted looking data to a file (encrypted)" {
            _encrypted_storage.write(_short_message.as_bytes()).expect("The write should be successful");

            let mut contents : Vec<u8> = Vec::new();
            let mut file = fs::File::open("test_dir/database").expect("File should exist and open properly");
            file.read_to_end(&mut contents).expect("File should be read properly");
            let encrypted_contents = String::from_utf8_lossy(&contents);

            assert_eq!(encrypted_contents.contains("Short message"), false);
        }

        it "should write plaintext data to a file (plaintext)" {
            _plaintext_storage.write(_short_message.as_bytes()).expect("The write should be successful");

            let mut contents : Vec<u8> = Vec::new();
            let mut file = fs::File::open("test_dir/plaintext").expect("File should exist and open properly");
            file.read_to_end(&mut contents).expect("File should be read properly");
            let contents = String::from_utf8_lossy(&contents);

            assert_eq!(contents.contains("Short message"), true);
        }

        ignore "should write CHACHA20 POLY1305 data to a file (encrypted)" {
            // TODO: How to actually validate the encryption, without relying on code that we've written?
            // Third party tools? Other?
        }

        it "should be able to read the encrypted file (encrypted)" {
            _encrypted_storage.write(_short_message.as_bytes()).expect("The write should be successful");

            // Read it back, convert it to a string and make sure it's equal
            let mut sealed_buffer: Vec<u8> = Vec::new();

            let plaintext = _encrypted_storage.read(&mut sealed_buffer).expect("The read should be successful");

            let plaintext = String::from_utf8_lossy(plaintext);
            assert_eq!(plaintext, "Short message");
        }

        it "should be able to read the plaintext file (plaintext)" {
            _plaintext_storage.write(_short_message.as_bytes()).expect("The write should be successful");

            // Read it back, convert it to a string and make sure it's equal
            let mut sealed_buffer: Vec<u8> = Vec::new();
            let plaintext = _plaintext_storage.read(&mut sealed_buffer).expect("The read should be successful");

            let plaintext = String::from_utf8_lossy(plaintext);
            assert_eq!(plaintext, "Short message");
        }

        it "should return an error if the Key Length is incorrect" {
            let key: &[u8] = b"7b6300f7dc21c9fddeaa71f439d53b551"; // 1 extra byte
            let storage = EncryptedStorage::new(path::PathBuf::from("test_dir/database"), key.to_vec());

            let result = storage.write(_short_message.as_bytes());

            assert!(match result.unwrap_err() {
                StorageError::KeyLengthError => true,
                _ => false
            });
        }

        it "should return an error the data was encrypted with a different key" {
            _encrypted_storage.write(_short_message.as_bytes()).expect("The write should be successful");

            let key: &[u8] = b"7b6300f7dc21c9fddeaa71f439d53b56"; // ending b55 => b56
            let storage = EncryptedStorage::new(path::PathBuf::from("test_dir/database"), key.to_vec());

            let mut sealed_buffer: Vec<u8> = Vec::new();
            let result = storage.read(&mut sealed_buffer);

            assert!(match result.unwrap_err() {
                StorageError::DecryptionError => true,
                _ => false
            });
        }
    }

    fn ensure_test_dir() {
        fs::remove_dir_all("test_dir").unwrap_or(());
        fs::create_dir_all("test_dir").unwrap_or(());
    }

    fn remove_test_dir() {
        fs::remove_dir_all("test_dir").unwrap_or(());
    }
}
