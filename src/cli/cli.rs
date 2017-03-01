#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate vault_core;

use vault_core::database::Database;

static KEY: &'static [u8] = b"7b6300f7dc21c9fddeaa71f439d53b55";
static READ_KEY: &'static [u8] = b"7b6300f7dc21c9fddeaa71f439d53b55";

pub fn main() {
    let db = Database::new(KEY.to_vec());
    let msg = String::from("This is a test of the encrypted storage and database mechanisms");

    db.write(msg.as_bytes());
    println!("Writing to database: {}", db.path.display());
    println!("Wrote message: {}", msg);

    let read_db = Database::new(READ_KEY.to_vec());

    let mut s = String::new();
    read_db.read_string(&mut s);
    println!("Read message back from the database: {}", s);
    // let msg = String::from("Hello world, this is rust");
    // write_database(msg.as_bytes(), KEY.to_vec());
    //
    // let mut s = String::new();
    //
    // read_database_string(&mut s, &KEY);
    //
    // println!("Read from the database: {}", s);
}
