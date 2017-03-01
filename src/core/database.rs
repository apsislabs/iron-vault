extern crate ring;
extern crate itertools;
extern crate odds;

use std::env;
use std::io::prelude::*;
use std::fs::File;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::str::from_utf8;
use std::vec::Vec;
use self::ring::aead;
use self::ring::aead::seal_in_place;
use self::ring::aead::open_in_place;
use self::ring::rand::SystemRandom;
use self::itertools::Itertools;
use self::odds::vec::VecExt;

static ENVIRONMENT_KEY: &'static str = "IRONVAULT_DATABASE";
static DEFAULT_DATABASE_PATH: &'static str = "/.ironvault/database";

static KEY: &'static [u8] = b"7b6300f7dc21c9fddeaa71f439d53b553a7bf3e69ff515b5cb6495d652a0f99c";

// Next steps:
// 1. Pass in the key
// 2. Create some kind of actual structure that can be used.
// 3. Break into `database.rs` and `encrypted_storage.rs`
// 4. Code cleanup
// 5. Unit tests

pub fn read_database(buf: &mut String) {
    let db_path = resolve_database_path();
    let mut f = File::open(db_path).expect("Failed to open the database file");

    let mut sealed_buffer : Vec<u8> = Vec::new();
    f.read_to_end(&mut sealed_buffer).expect("Failed to read the database file into the provided string buffer");

    println!("Opened database ciphertext: {:02x}", sealed_buffer.iter().format(""));

    open_data(&mut sealed_buffer);

    buf.clear();
    buf.push_str(&format!("{:02x}", sealed_buffer.iter().format("")));
}

pub fn write_database(buf: &[u8]) {
    let db_path = resolve_database_path();
    let mut f = File::create(db_path).expect("Failed to open the database file");
    let mut data = buf.to_vec();

    println!("Sealing plaintext: {}", from_utf8(&data[..]).unwrap());

    let ciphertext = seal_data(&mut data);

    println!("In write database ciphertext: {:02x}", ciphertext.iter().format(""));

    f.write_all(ciphertext).expect("Failed to write the provided string buffer into the database file");
}

fn open_data(data: &mut Vec<u8>) {
    let chacha20_poly1305 = &aead::CHACHA20_POLY1305;
    let key_len = chacha20_poly1305.key_len();
    let nonce_len = chacha20_poly1305.nonce_len();

    let opening_key = aead::OpeningKey::new(chacha20_poly1305, &KEY[..key_len]).expect("Should have generated the sealing key");

    let ad: [u8; 0] = [0; 0];

    let nonce = data[..nonce_len].to_vec();

    let plaintext = open_in_place(&opening_key, &nonce, &ad[..], nonce_len, &mut data[..]).expect("Should have opened in place properly.");

    println!("Unsealed plaintext: {} [len {}]", from_utf8(plaintext).unwrap(), plaintext.len());
}

fn seal_data(data: &mut Vec<u8>) -> &[u8] {
    let chacha20_poly1305 = &aead::CHACHA20_POLY1305;
    let tag_len = chacha20_poly1305.tag_len();
    let key_len = chacha20_poly1305.key_len();
    let nonce_len = chacha20_poly1305.nonce_len();

    let sealing_key = aead::SealingKey::new(chacha20_poly1305, &KEY[..key_len]).expect("Should have generated the sealing key");
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

fn determine_database_path(path: Option<&str>) -> String {
    // 1 - Explicit Override Resolution
    if path.is_some() { return String::from(path.unwrap()); }

    // 2 - Environment Variable Resolution
    let environment_result = env::var(ENVIRONMENT_KEY);
    if environment_result.is_ok() { return environment_result.unwrap(); }

    // 3 - Hardcoded Resolution
    let home_dir = env::home_dir().expect("Failed to find the home directory");
    return format!("{}{}", home_dir.display(), DEFAULT_DATABASE_PATH);
}

fn resolve_database_path() -> PathBuf {
    let path = determine_database_path(None);

    let path = PathBuf::from(&path);

    match path.parent() {
        Some(parent) => create_dir_all(parent).expect("Failed to create the directory for the database"),
        _            => panic!("The path didn't have a parent attribute.")
    }

    return path;
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::remove_dir_all;
    use std::path::Path;

    #[test]
    fn determine_database_path_with_environment_variable() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "~/test_tmp/ironvault");
            assert_eq!(determine_database_path(None), "~/test_tmp/ironvault");
        });
    }

    #[test]
    fn determine_database_path_with_default_directory() {
        test_cleanup(&|| {
            assert!(determine_database_path(None).ends_with("/.ironvault/database"));
        });
    }

    #[test]
    fn determine_database_path_with_explicit_path() {
        test_cleanup(&|| {
            assert_eq!(determine_database_path(Some("~/.test_tmp/ironvault-explicit")), "~/.test_tmp/ironvault-explicit");
        });
    }

    #[test]
    fn resolve_database_path_creates_a_directory() {
        test_cleanup(&|| {
            env::set_var(ENVIRONMENT_KEY, "test_dir/something/ironvault");

            assert!( !Path::new("test_dir").is_dir() );
            assert!( !Path::new("test_dir/something").is_dir() );
            assert!( !Path::new("test_dir/something/ironvault").is_dir() );

            let db_path = resolve_database_path();
            println!("{}", db_path.display());

            assert!( Path::new("test_dir").is_dir() );
            assert!( Path::new("test_dir/something").is_dir() );
            assert!( !Path::new("test_dir/something/ironvault").is_dir() );
        });
    }

    fn test_cleanup(tests_fn: &Fn()) {
        perform_cleanup();
        tests_fn();
        perform_cleanup();
    }

    fn perform_cleanup() {
        remove_test_dir();
        env::remove_var(ENVIRONMENT_KEY);
    }

    fn remove_test_dir() {
        remove_dir_all("test_dir").unwrap_or(())
    }
}
