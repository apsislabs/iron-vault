#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate vault_core;

use vault_core::database::Database;
use vault_core::database::Configuration;
use vault_core::record::Record;

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

    let config = reopened_db.config();
    println!("A database config: {:?}", config);

    let config_json = config.to_json();
    println!("config json: {}", config_json);

    let other_config = Configuration::from_json(config_json);
    println!("Other database config: {:?}", other_config);

    let record = Record::new_password("My First Password".to_string(), "noah".to_string(), "password1".to_string());
    println!("Generated a new password {:?}", record);
    println!("Converted password to json: {}", record.to_json());

    let other_record = Record::from_json(record.to_json());
    println!("Password parsed from json {:?}", other_record);
}
