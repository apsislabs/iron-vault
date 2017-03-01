extern crate vault_core;

use vault_core::database::read_database;
use vault_core::database::write_database;

pub fn main() {
    let msg = String::from("Hello world, this is rust");
    write_database(msg.as_bytes());

    let mut s = String::new();

    read_database(&mut s);

    println!("Read from the database: {}", s);
}
