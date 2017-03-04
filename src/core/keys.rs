use std::vec::Vec;
use ring::aead;
use ring::rand;
use ring::pbkdf2;

pub fn generate_encryption_key(algorithm: &'static aead::Algorithm) -> Vec<u8> {
    let key_len = algorithm.key_len();
    let rng = rand::SystemRandom::new();

    let mut encryption_key: Vec<u8> = vec![0; key_len];
    rng.fill(&mut encryption_key).expect("Should have generated the key successfully");

    return encryption_key;
}

pub fn derive_key(algorithm: &'static aead::Algorithm, password: String) -> Vec<u8> {
    let key_len = algorithm.key_len();
    let iterations = 100000;

    let salt: [u8; 16] = [ // TODO: Generate a new salt
        0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52,
        0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a
    ];

    let mut derived_key: Vec<u8> = Vec::with_capacity(key_len);
    derived_key.resize(key_len, 0);
    pbkdf2::derive(&pbkdf2::HMAC_SHA256, iterations, &salt,
                       password.as_bytes(), &mut derived_key);

    return derived_key;
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
