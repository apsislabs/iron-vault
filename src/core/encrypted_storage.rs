use std::io::prelude::*;
use std::fs;
use std::path;
use std::vec::Vec;
use ring::aead;
use ring::rand;
use odds::vec::VecExt;

// Next steps:
// 1. Code cleanup
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

    pub fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a [u8] {
        return read_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }

    pub fn write(&self, buffer: &[u8]) {
        return write_encrypted(&self.path, buffer, &self.key, &self.algorithm);
    }
}

fn read_encrypted<'a, P: AsRef<path::Path>>(path: P,
                                            buffer: &'a mut Vec<u8>,
                                            key: &[u8],
                                            algorithm: &'static aead::Algorithm)
                                            -> &'a [u8] {
    let mut f = fs::File::open(path).expect("Failed to open the database file");

    buffer.clear();
    f.read_to_end(buffer)
        .expect("Failed to read the database file into the provided string buffer");

    return open_data(buffer, key, algorithm);
}

fn write_encrypted<P: AsRef<path::Path>>(path: P,
                                         buf: &[u8],
                                         key: &[u8],
                                         algorithm: &'static aead::Algorithm) {
    let mut f = fs::File::create(path).expect("Failed to open the database file");
    let mut data = buf.to_vec();

    let ciphertext = seal_data(&mut data, key, algorithm);

    f.write_all(ciphertext)
        .expect("Failed to write the provided string buffer into the database file");
}

fn open_data<'a>(data: &'a mut Vec<u8>,
                 key: &[u8],
                 algorithm: &'static aead::Algorithm)
                 -> &'a [u8] {
    let key_len = algorithm.key_len();
    let nonce_len = algorithm.nonce_len();

    let opening_key = aead::OpeningKey::new(algorithm, &key[..key_len])
        .expect("Should have generated the sealing key");

    let ad: [u8; 0] = [0; 0];

    let nonce = data[..nonce_len].to_vec();

    let plaintext = aead::open_in_place(&opening_key, &nonce, &ad[..], nonce_len, &mut data[..])
        .expect("Should have opened in place properly.");

    return plaintext;
}

fn seal_data<'a>(data: &'a mut Vec<u8>,
                 key: &[u8],
                 algorithm: &'static aead::Algorithm)
                 -> &'a [u8] {
    let tag_len = algorithm.tag_len();
    let key_len = algorithm.key_len();
    let nonce_len = algorithm.nonce_len();

    let sealing_key = aead::SealingKey::new(algorithm, &key[..key_len])
        .expect("Should have generated the sealing key");

    let mut nonce: Vec<u8> = vec![0; nonce_len];

    let rng = rand::SystemRandom::new();
    rng.fill(&mut nonce).expect("Should have filled out the nonce");

    let ad: [u8; 0] = [0; 0];

    for _ in 0..tag_len {
        data.push(0);
    }

    let ciphertext_size =
        aead::seal_in_place(&sealing_key, &nonce, &ad[..], &mut data[..], tag_len)
            .expect("Should have sealed in place properly");

    data.splice(..0, nonce);

    let encrypted_len = nonce_len + ciphertext_size;

    return &data[..encrypted_len];
}
