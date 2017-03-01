use std::io::prelude::*;
use std::io;
use std::error;
use std::fmt;
use std::fs;
use std::path;
use std::vec::Vec;
use ring::aead;
use ring::rand;
use odds::vec::VecExt;

// Next steps:
// 2. Error handling
// 3. Unit tests
// 4. Documentation

pub struct EncryptedStorage {
    path: path::PathBuf,
    key: Vec<u8>,
    algorithm: &'static aead::Algorithm,
}

impl EncryptedStorage {
    pub fn new(path: path::PathBuf, key: Vec<u8>) -> EncryptedStorage {
        EncryptedStorage {
            path: path,
            key: key,
            algorithm: &aead::CHACHA20_POLY1305,
        }
    }

    pub fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8], StorageError> {
        return read_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }

    pub fn write(&self, buffer: &[u8]) -> Result<(), StorageError> {
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
    FileError(io::Error),
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
        }
    }
}

fn read_encrypted<'a, P: AsRef<path::Path>>(path: P,
                                            buffer: &'a mut Vec<u8>,
                                            key: &[u8],
                                            algorithm: &'static aead::Algorithm)
                                            -> Result<&'a [u8], StorageError> {
    let mut f = try!(fs::File::open(path).map_err(StorageError::FileError));

    buffer.clear();
    try!(f.read_to_end(buffer).map_err(StorageError::FileError));

    return open_data(buffer, key, algorithm);
}

fn write_encrypted<P: AsRef<path::Path>>(path: P,
                                         buf: &[u8],
                                         key: &[u8],
                                         algorithm: &'static aead::Algorithm)
                                         -> Result<(), StorageError> {
    let mut f = try!(fs::File::create(path).map_err(StorageError::FileError));
    let mut data = buf.to_vec();

    let ciphertext = try!(seal_data(&mut data, key, algorithm));

    try!(f.write_all(ciphertext).map_err(StorageError::FileError));

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
