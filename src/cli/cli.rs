extern crate vault_core;

use vault_core::database::Database;

static KEY: &'static [u8] = b"7b6300f7dc21c9fddeaa71f439d53b553a7bf3e69ff515b5cb6495d652a0f99c";

pub fn main() {
    let db = Database::new(KEY.to_vec());
    let msg = String::from("This is a test of the encrypted storage and database mechanisms");

    db.write(msg.as_bytes());
    println!("Wrote message to database: {}", msg);

    let mut s = String::new();
    db.read_string(&mut s);
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
