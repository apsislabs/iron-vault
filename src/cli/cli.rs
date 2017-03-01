extern crate vault_core;

use vault_core::database::read_database_string;
use vault_core::database::write_database;

static KEY: &'static [u8] = b"7b6300f7dc21c9fddeaa71f439d53b553a7bf3e69ff515b5cb6495d652a0f99c";

pub fn main() {
    let msg = String::from("Hello world, this is rust");
    write_database(msg.as_bytes(), KEY.to_vec());

    let mut s = String::new();

    read_database_string(&mut s, &KEY);

    println!("Read from the database: {}", s);
}
