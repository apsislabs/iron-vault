# Iron Vault

[![Build Status](https://travis-ci.org/apsislabs/iron-vault.svg?branch=master)](https://travis-ci.org/apsislabs/iron-vault)

Iron Vault is a _toy_ password manager written in Rust. While the goal is to design
a secure system for managing passwords, it was not designed by a security expert and
has not been independently audited or evaluated by security experts.

As such it cannot be expressed strongly enough that Iron Vault is a _toy_ password manager. **UNDER NO CIRCUMSTANCES SHOULD YOU PUT REAL PASSWORDS INTO IRON VAULT**.

## Architecture

Iron Vault is broken up into a number of separate components. The core logic exists in a rust library known as `vault_core`. The main file for this library exists in `src/core/core.rs`. `vault_core` is responsible for all of the core cryptographic strength of Iron Vault.

The application that provides command line access to your encrypted passwords is a rust program called `iv`. The main entry point for `iv` is in `src/cli/cli.rs`.

In the future there will also exist:
* A rust application `vault_service` that runs as a service and provides access to vault for `iv` and other applications.
* An electron application to provide a native desktop application for Iron Vault.
* A Chrome and Firefox browser extension to provide a browser application for Iron Vault.

## Development

### Getting Started

Ensure you have all of the development dependencies installed (see below). Once that's done, run `bin/setup` to initialize the repository.

Building everything can be run with `cargo build`.

### Development Dependencies

(Right now we require the nightly rust because we rely on `stainless` for unit tests. This is something we want to change to get back onto the stable build of rust)

* Rustup (https://www.rustup.rs/)
* Nightly rust:
** `rustup install nightly`
** `rustup default nightly`

### Building

To build simply run `cargo build`.

### Testing

Tests are run with Cargo. Unfortunately, due to the environment variable testing in
`database.rs`, tests can only be run on a single thread or you will see some
intermittent errors. To run tests execute:

```
RUST_TEST_THREADS=1 cargo test
```

Some of the PBKDF2 tests are slow and are ignored for the main run of tests. To test these functions run:

```
RUST_TEST_THREADS=1 cargo test -- --ignored
```

Both of these tests will be run automatically by the pre-push hooks that are installed with `bin/setup`.
