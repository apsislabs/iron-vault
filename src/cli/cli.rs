#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate vault_core;

use std::env;

use vault_core::vault::Vault;
use vault_core::record::Record;

static PASSWORD: &'static str = "My voice is my password, verify me";

enum IronVaultAction {
    Create,
    Add,
    Read,
    List
}

pub fn main() {
    let mut args = env::args();
    let action_arg = args.nth(1).unwrap_or("l".to_string());
    let action = match action_arg.as_ref() {
        "c" => IronVaultAction::Create,
        "r" => IronVaultAction::Read,
        "a" => IronVaultAction::Add,
        _   => IronVaultAction::List,
    };

    match action {
        IronVaultAction::Create => {
            Vault::create(PASSWORD.to_string(), None).expect("There was an error creating the vault");
            println!("Created the new vault. Neat!");
        }
        IronVaultAction::List => {
            let vault = Vault::open(PASSWORD.to_string(), None).expect("There was an error opening the vault!");
            let records = vault.fetch_records();
            let record_names: Vec<String> = records.iter().map(|ref record| record.name.clone()).collect();

            println!("Listing the records: {:?}", record_names);
        }
        IronVaultAction::Add => {
            let mut vault = Vault::open(PASSWORD.to_string(), None).expect("There was an error opening the vault!");
            let vault_size = vault.fetch_records().len();
            let record_name = format!("Record {}", vault_size + 1);
            let username = "test@example.com".to_string();
            let password = format!("p@ssword{}", vault_size + 1);
            let record = Record::new_login(record_name, username, password);

            vault.add_record(record.clone()).expect("There was an error adding the record.");

            println!("Added new record: {:?}", record);
        }
        IronVaultAction::Read => {
            let record_name = "Record 2".to_string();
            let vault = Vault::open(PASSWORD.to_string(), None).expect("There was an error opening the vault!");
            let records = vault.get_records_by_name(record_name.clone());

            println!("Record for {}: {:?}", record_name, records);
        }
    }
}
