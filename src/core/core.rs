#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate ring;
extern crate odds;

// TODO: encrypted_storage should not be `pub`. This is done temporarily for doc generation purposes
// while working on the 0.2.0 release.
pub mod encrypted_storage;
pub mod database;
