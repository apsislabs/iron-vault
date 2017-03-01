extern crate vault_core;

use vault_core::database::read_database;
use vault_core::database::write_database;

pub fn main() {
    write_database(b"Hello World, Maybe");

    let mut s = String::new();

    read_database(&mut s);

    println!("Read from the database: {}", s);
}
