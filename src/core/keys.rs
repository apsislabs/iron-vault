use std::vec::Vec;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use ring::aead;
use ring::rand;
use ring::pbkdf2;

const ITERATIONS_BASE_COUNT     : u32 = 100000;
const ITERATIONS_EXTENSION_COUNT: u32 = 10000;

// Next Steps:
// 1. Randomize and store/retrieve salt
// 2. Code cleanup and last unit tests
// 3. Documentation.

pub fn generate_encryption_key(algorithm: &'static aead::Algorithm) -> Vec<u8> {
    let key_len = algorithm.key_len();
    let rng = rand::SystemRandom::new();

    let mut encryption_key: Vec<u8> = vec![0; key_len];
    rng.fill(&mut encryption_key).expect("Should have generated the key successfully");

    return encryption_key;
}

pub fn derive_key(algorithm: &'static aead::Algorithm, password: String) -> Vec<u8> {
    let key_len = algorithm.key_len();

    let salt: [u8; 16] = [ // TODO: Generate a new salt
        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52,
        0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a
    ];

    let mut derived_key: Vec<u8> = Vec::with_capacity(key_len);
    derived_key.resize(key_len, 0);
    pbkdf2::derive(&pbkdf2::HMAC_SHA256, iterations(password.clone()), &salt,
                       password.as_bytes(), &mut derived_key);

    return derived_key;
}

/// Determine the total number of iterations to use for the given password. Theoretically this will
/// make GPU attacks more challenging, as the attack process isn't as parallelizable given the need
/// to branch based on the hash value of the string.
fn iterations(password: String) -> u32 {
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let iteration_extensions = hasher.finish() as u32 % ITERATIONS_EXTENSION_COUNT;

    let iterations: u32 = ITERATIONS_BASE_COUNT + iteration_extensions;

    // Ensure we haven't overflowed our u32 size in some way
    assert!(iterations > ITERATIONS_BASE_COUNT);

    return iterations;
}

#[cfg(test)]
mod test {
    use super::*;

    describe! generate_encryption_key {
        it "should produce keys of the correct length" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(generate_encryption_key(alg).len() == alg.key_len());

            let alg = &aead::AES_128_GCM;
            assert!(generate_encryption_key(alg).len() == alg.key_len());

            let alg = &aead::AES_256_GCM;
            assert!(generate_encryption_key(alg).len() == alg.key_len());
        }

        it "should produce different keys" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(generate_encryption_key(alg) != generate_encryption_key(alg));
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
        ignore "should produce keys of the correct length" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(derive_key(alg, String::from("hello")).len() == alg.key_len());

            let alg = &aead::AES_128_GCM;
            assert!(derive_key(alg, String::from("hello")).len() == alg.key_len());

            let alg = &aead::AES_256_GCM;
            assert!(derive_key(alg, String::from("hello")).len() == alg.key_len());
        }

        ignore "should derive the same key for the same password" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(derive_key(alg, String::from("hello")) == derive_key(alg, String::from("hello")));
        }

        ignore "should derive different keys for different passwords" {
            let alg = &aead::CHACHA20_POLY1305;
            assert!(derive_key(alg, String::from("hello")) != derive_key(alg, String::from("hell")));
        }
    }
}
