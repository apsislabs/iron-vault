#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate vault_core;

use vault_core::database::Database;

static PASSWORD: &'static str = "My voice is my password, verify me";

pub fn main() {
    let db = Database::create(String::from(PASSWORD));
    let msg = String::from("This is a test of the encrypted storage and database mechanisms");

    db.write(msg.as_bytes());
    println!("Writing to database: {}", db.path.display());
    println!("Wrote message: {}", msg);

    let mut s = String::new();
    db.read_string(&mut s);
    println!("Read message back from the database: {}", s);

    // Re-open the database and try again
    let mut s_again = String::new();
    let reopened_db = Database::open(String::from(PASSWORD));
    reopened_db.read_string(&mut s_again);
    println!("Message from reopend db: {}", s_again);

}
