extern crate ring;
// extern crate itertools;
extern crate odds;

use std::io::prelude::*;
use std::fs::File;
use std::path::PathBuf;
use std::path::Path;
use std::vec::Vec;
use self::ring::aead;
use self::ring::aead::Algorithm;
use self::ring::aead::seal_in_place;
use self::ring::aead::open_in_place;
use self::ring::rand::SystemRandom;
use self::odds::vec::VecExt;

// Next steps:
// 1. Code cleanup
// 2. Error handling
// 3. Unit tests

pub struct EncryptedStorage {
    path: PathBuf,
    key:  Vec<u8>,
    algorithm: &'static Algorithm,
}

impl EncryptedStorage {
    pub fn new(path: PathBuf, key: Vec<u8>) -> EncryptedStorage {
        EncryptedStorage {
            path: path,
            key: key,
            algorithm: &aead::CHACHA20_POLY1305,
        }
    }

    pub fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a[u8] {
        return read_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }

    pub fn write(&self, buffer: &[u8]) {
        return write_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }
}

fn read_encrypted<'a, P: AsRef<Path>>(path: P, buffer: &'a mut Vec<u8>, key: &[u8], algorithm: &'static Algorithm) -> &'a[u8] {
    let mut f = File::open(path).expect("Failed to open the database file");

    buffer.clear();
    f.read_to_end(buffer).expect("Failed to read the database file into the provided string buffer");

    return open_data(buffer, key, algorithm);
}

fn write_encrypted<P: AsRef<Path>>(path: P, buf: &[u8], key: &[u8], algorithm: &'static Algorithm) {
    let mut f = File::create(path).expect("Failed to open the database file");
    let mut data = buf.to_vec();

    let ciphertext = seal_data(&mut data, key, algorithm);

    f.write_all(ciphertext).expect("Failed to write the provided string buffer into the database file");
}

fn open_data<'a>(data: &'a mut Vec<u8>, key: &[u8], algorithm: &'static Algorithm) -> &'a [u8] {
    let key_len = algorithm.key_len();
    let nonce_len = algorithm.nonce_len();

    let opening_key = aead::OpeningKey::new(algorithm, &key[..key_len]).expect("Should have generated the sealing key");

    let ad: [u8; 0] = [0; 0];

    let nonce = data[..nonce_len].to_vec();

    let plaintext = open_in_place(&opening_key, &nonce, &ad[..], nonce_len, &mut data[..]).expect("Should have opened in place properly.");

    return plaintext;
}

fn seal_data<'a>(data: &'a mut Vec<u8>, key: &[u8], algorithm: &'static Algorithm) -> &'a [u8] {
    let tag_len = algorithm.tag_len();
    let key_len = algorithm.key_len();
    let nonce_len = algorithm.nonce_len();

    let sealing_key = aead::SealingKey::new(algorithm, &key[..key_len]).expect("Should have generated the sealing key");

    let mut nonce: Vec<u8> = vec![0; nonce_len];

    let rng = SystemRandom::new();
    rng.fill(&mut nonce).expect("Should have filled out the nonce");

    let ad: [u8; 0] = [0; 0];

    for _ in 0..tag_len {
        data.push(0);
    }

    let ciphertext_size = seal_in_place(&sealing_key, &nonce, &ad[..], &mut data[..], tag_len).expect("Should have sealed in place properly");

    data.splice(..0, nonce);

    let encrypted_len = nonce_len + ciphertext_size;

    return &data[..encrypted_len];
}
