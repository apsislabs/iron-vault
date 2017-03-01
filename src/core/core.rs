#![feature(plugin)]
#![cfg_attr(test, plugin(stainless))]

extern crate ring;
extern crate odds;

mod encrypted_storage;
pub mod database;
