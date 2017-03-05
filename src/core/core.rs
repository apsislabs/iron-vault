#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

#[macro_use]
extern crate serde_derive;

extern crate serde_json;
extern crate ring;
extern crate odds;
extern crate uuid;

// TODO: encrypted_storage should not be `pub`. This is done temporarily for doc generation purposes
// while working on the 0.2.0 release.
pub mod encrypted_storage;
pub mod keys;

pub mod database;
pub mod record;
