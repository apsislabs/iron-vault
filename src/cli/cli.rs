#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate vault_core;

use vault_core::database::Database;
use vault_core::database::Configuration;
use vault_core::record::Record;

static PASSWORD: &'static str = "My voice is my password, verify me";

pub fn main() {
    let db = Database::create(String::from(PASSWORD));
    let record = Record::new_login("My First Password".to_string(), "noah".to_string(), "password1".to_string());

    println!("Writing record {:?} to database {}.", record, db.path.display());
    db.write_record(record);

    let updated_record = db.read_record();
    println!("Read record {:?} from database.", updated_record);

    // Fetch, store and reload the config...
    let config = db.config();
    println!("A database config: {:?}", config);

    let config_json = config.to_json();
    println!("config json: {}", config_json);

    let other_config = Configuration::from_json(config_json);
    println!("Other database config: {:?}", other_config);
}
