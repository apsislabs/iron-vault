#![feature(plugin)]
#![feature(splice)]
#![cfg_attr(test, plugin(stainless))]

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate ring;
extern crate uuid;

// TODO: storage, keys should not be `pub`. This is done temporarily for doc generation purposes
// while working on the 0.2.0 release.
pub mod storage;
pub mod keys;

pub mod vault;
pub mod record;
