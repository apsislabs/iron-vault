extern crate vault_core;

use vault_core::print_core;
use vault_core::database::print_database;

pub fn main() {
    println!("main");
    print_core();
    print_database();
}
