use std::collections::hash_map::DefaultHasher;
use std::error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::vec::Vec;
use ring::aead;
use ring::rand;
use ring::digest;
use ring::pbkdf2;

// CONFIGURABLE
const SALT_LEN                  : usize = 16;
const ITERATIONS_BASE_COUNT     : u32   = 100000;
const ITERATIONS_EXTENSION_COUNT: u32   = 10000;

/// Generate a new key for the given algorithm using the given source of randomness.
///
/// # Errors
/// * `KeyError::KeyGenerationError` if the source of randomness throws an error
pub fn generate_key(algorithm: &'static aead::Algorithm, random: &rand::SecureRandom) -> Result<Vec<u8>, KeyError> {
    // Create a vector with enough space for our key
    let mut encryption_key: Vec<u8> = vec![0; algorithm.key_len()];

    // Fill the key using the system's secure random number generation provided by ring.
    random.fill(&mut encryption_key).map_err(|_| KeyError::KeyGenerationError)?;

    return Ok(encryption_key);
}

/// Derives a key for the given algorithm, using the provided salt and password. This uses PBKDF2
/// (HMAC SHA256) to derive the key. The number of iterations is set at 100,000 plus 0-10000 based on
/// password string (for a total number of iterations between 100,000 and 110,000).
///
/// # Errors
/// * `KeyError::SaltLengthError` if the salt is too short (less than or equal to four bytes)
pub fn derive_key(algorithm: &'static aead::Algorithm, salt: &[u8], password: String) -> Result<Vec<u8>, KeyError> {
    // Just bugger off if you have a weak salt
    if salt.len() <= 4 {
        return Err(KeyError::SaltLengthError);
    }

    // Create a vector with enough space for our key
    let mut derived_key: Vec<u8> = vec![0; algorithm.key_len()];

    // Derive the key using ring (thanks ring!)
    // CONFIGURABLE (key derivation algorith, PRF (HMAC_SHA256) for key derivation algorithm)
    pbkdf2::derive(&digest::SHA256, iterations(password.clone()), salt,
                       password.as_bytes(), &mut derived_key);

    return Ok(derived_key);
}

/// Generates a salt that can be used when deriving a key.
//
/// # Errors
/// * `KeyError::SaltGenerationError` if the source of randomness throws an error
pub fn generate_salt(random: &rand::SecureRandom) -> Result<Vec<u8>, KeyError> {
    let mut salt: Vec<u8> = vec![0; SALT_LEN];
    random.fill(&mut salt).map_err(|_| KeyError::SaltGenerationError)?;
    return Ok(salt);
}

/// Determine the total number of iterations to use for the given password. Theoretically this will
/// make GPU attacks more challenging, as the attack process isn't as parallelizable given the need
/// to branch based on the hash value of the string.
fn iterations(password: String) -> u32 {
    // Calculate a (non-secure) hash of the password, to determine how many extra steps we will use
    // based on this password.
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let hash = hasher.finish() as u32;
    let iteration_extensions = hash % ITERATIONS_EXTENSION_COUNT;

    let iterations: u32 = ITERATIONS_BASE_COUNT + iteration_extensions;

    // Ensure we haven't overflowed our u32 size in some way
    assert!(iterations > ITERATIONS_BASE_COUNT);

    return iterations;
}

#[derive(Debug)]
pub enum KeyError {
    KeyGenerationError,
    SaltGenerationError,
    SaltLengthError,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyError::KeyGenerationError => {
                write!(f,
                       "There was a problem generating the key from the system's random values.")
            }
            KeyError::SaltLengthError => {
                write!(f, "The given salt was too short.")
            }
            KeyError::SaltGenerationError => write!(f, "There was a problem generating the salt from the system's random values.")
        }
    }
}

impl error::Error for KeyError {
    fn description(&self) -> &str {
        match *self {
            KeyError::KeyGenerationError => {
                "There was a problem generating the key from the system's random values."
            }
            KeyError::SaltLengthError => {
                "The given salt was too short."
            }
            KeyError::SaltGenerationError => {
                "There was a problem generating the salt from the system's random values."
            }
        }
    }

    fn cause(&self) -> Option<&error::Error> { None }
}

#[cfg(test)]
mod test {
    use super::*;

    describe! generate_key {
        before_each {
            let random = &rand::SystemRandom::new();
        }

        it "should produce keys of the correct length" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(generate_key(alg, random).unwrap().len() == alg.key_len());

            let alg = &aead::AES_128_GCM;
            assert!(generate_key(alg, random).unwrap().len() == alg.key_len());

            let alg = &aead::AES_256_GCM;
            assert!(generate_key(alg, random).unwrap().len() == alg.key_len());
        }

        it "should produce different keys" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(generate_key(alg, random).unwrap() != generate_key(alg, random).unwrap());
        }
    }

    describe! iterations {
        it "should produce different iterations for different passwords" {
            assert!(iterations("hello".to_string()) != iterations("hell".to_string()));
        }

        it "should produce the same iterations for the same passwords" {
            assert!(iterations("hello".to_string()) == iterations("hello".to_string()));
        }

        it "should always produce iterations above the base" {
            assert!(iterations("hello".to_string()) > ITERATIONS_BASE_COUNT);
            assert!(iterations("hell".to_string()) > ITERATIONS_BASE_COUNT);
            assert!(iterations("This is a really quite very long password".to_string()) > ITERATIONS_BASE_COUNT);
            assert!(iterations("goodbye".to_string()) > ITERATIONS_BASE_COUNT);
            assert!(iterations("timbuk2".to_string()) > ITERATIONS_BASE_COUNT);
        }
    }

    describe! derive_key {
        before_each {
            let _salt: [u8; 16] = [0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a];
            let alg = &aead::CHACHA20_POLY1305;
        }

        failing "should fail if the salt is too short" {
            let _salt: [u8; 2] = [0xd6, 0x26];
            derive_key(alg, &_salt, "hello".to_string()).unwrap();
        }

        ignore "should derive different keys for the same password with different salts" {
            let key_a = derive_key(alg, &_salt, "hello".to_string()).unwrap();
            let _salt: [u8; 16] = [0xe6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a];
            let key_b = derive_key(alg, &_salt, "hello".to_string()).unwrap();

            assert!(key_a != key_b);
        }

        ignore "should produce keys of the correct length" {
            assert!(derive_key(alg, &_salt, "hello".to_string()).unwrap().len() == alg.key_len());

            let alg = &aead::AES_128_GCM;
            assert!(derive_key(alg, &_salt, "hello".to_string()).unwrap().len() == alg.key_len());

            let alg = &aead::AES_256_GCM;
            assert!(derive_key(alg, &_salt, "hello".to_string()).unwrap().len() == alg.key_len());
        }

        ignore "should derive the same key for the same password" {
            assert!(derive_key(alg, &_salt, "hello".to_string()).unwrap() == derive_key(alg, &_salt, "hello".to_string()).unwrap());
        }

        ignore "should derive different keys for different passwords" {
            assert!(derive_key(alg, &_salt, "hello".to_string()).unwrap() != derive_key(alg, &_salt, "hell".to_string()).unwrap());
        }
    }
}
