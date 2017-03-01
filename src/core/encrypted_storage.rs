extern crate ring;
extern crate itertools;
extern crate odds;

use std::io::prelude::*;
use std::fs::File;
use std::path::PathBuf;
use std::path::Path;
use std::str::from_utf8;
use std::vec::Vec;
use self::ring::aead;
use self::ring::aead::seal_in_place;
use self::ring::aead::open_in_place;
use self::ring::rand::SystemRandom;
use self::itertools::Itertools;
use self::odds::vec::VecExt;

// Next steps:
// 1. Create some kind of actual structure that can be used.
// 2. Code cleanup
// 3. Unit tests

pub struct EncryptedStorage {
    path: PathBuf,
    key:  Vec<u8>
}

impl EncryptedStorage {
    pub fn new(path: PathBuf, key: Vec<u8>) -> EncryptedStorage {
        EncryptedStorage {
            path: path,
            key: key
        }
    }

    pub fn read<'a>(&self, buffer: &'a mut Vec<u8>) -> &'a[u8] {
        return read_encrypted(&self.path, buffer, &self.key);
    }
}

pub fn read_encrypted<'a, P: AsRef<Path>>(path: P, buffer: &'a mut Vec<u8>, key: &[u8]) -> &'a[u8] {
    let mut f = File::open(path).expect("Failed to open the database file");

    buffer.clear();
    f.read_to_end(buffer).expect("Failed to read the database file into the provided string buffer");

    println!("Opened database ciphertext: {:02x}", buffer.iter().format(""));

    return open_data(buffer, key);
}

pub fn write_encrypted<P: AsRef<Path>>(path: P, buf: &[u8], key: &[u8]) {
    let mut f = File::create(path).expect("Failed to open the database file");
    let mut data = buf.to_vec();

    println!("Sealing plaintext: {}", from_utf8(&data[..]).unwrap());

    let ciphertext = seal_data(&mut data, key);

    println!("In write database ciphertext: {:02x}", ciphertext.iter().format(""));

    f.write_all(ciphertext).expect("Failed to write the provided string buffer into the database file");
}

fn open_data<'a>(data: &'a mut Vec<u8>, key: &[u8]) -> &'a [u8] {
    let chacha20_poly1305 = &aead::CHACHA20_POLY1305;
    let key_len = chacha20_poly1305.key_len();
    let nonce_len = chacha20_poly1305.nonce_len();

    let opening_key = aead::OpeningKey::new(chacha20_poly1305, &key[..key_len]).expect("Should have generated the sealing key");

    let ad: [u8; 0] = [0; 0];

    let nonce = data[..nonce_len].to_vec();

    let plaintext = open_in_place(&opening_key, &nonce, &ad[..], nonce_len, &mut data[..]).expect("Should have opened in place properly.");

    println!("Unsealed plaintext: {} [len {}]", from_utf8(plaintext).unwrap(), plaintext.len());

    return plaintext;
}

fn seal_data<'a>(data: &'a mut Vec<u8>, key: &[u8]) -> &'a [u8] {
    let chacha20_poly1305 = &aead::CHACHA20_POLY1305;
    let tag_len = chacha20_poly1305.tag_len();
    let key_len = chacha20_poly1305.key_len();
    let nonce_len = chacha20_poly1305.nonce_len();

    let sealing_key = aead::SealingKey::new(chacha20_poly1305, &key[..key_len]).expect("Should have generated the sealing key");
    // TODO Generate a real nonce using SecureRandom instead of using a const nonce
    let mut nonce: Vec<u8> = vec![0; nonce_len];
    println!("Generated nonce of len {}, {:02x}", nonce_len, nonce.iter().format(""));

    let rng = SystemRandom::new();
    rng.fill(&mut nonce).expect("Should have filled out the nonce");
    println!("Filled out the nonce   {}, {:02x}", nonce_len, nonce.iter().format(""));

    let ad: [u8; 0] = [0; 0];

    // Push the tag onto the end of our data
    for _ in 0..tag_len {
        data.push(0);
    }

    let ciphertext_size = seal_in_place(&sealing_key, &nonce, &ad[..], &mut data[..], tag_len).expect("Should have sealed in place properly");

    // let ciphertext = &data[..ciphertext_size];

    // println!("Sealed ciphertext: {:02x}", ciphertext.iter().format(""));

    data.splice(..0, nonce);

    let encrypted_len = nonce_len + ciphertext_size;

    // nonce.extend(data[..ciphertext_size].iter().cloned());

    println!("Nonce+ciphertext: {:02x}", data.iter().format(""));

    return &data[..encrypted_len];
}
