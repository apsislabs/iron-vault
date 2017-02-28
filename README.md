# Iron Vault

Iron Vault is a _toy_ password manager written in Rust. While the goal is to design
a secure system for managing passwords, it was not designed by a security expert and
has not been independently audited or evaluated by security experts.

As such it cannot be expressed strongly enough that Iron Vault is a _toy_ password manager. **UNDER NO CIRCUMSTANCES SHOULD YOU PUT REAL PASSWORDS INTO IRON VAULT**.

## Dependencies

* Rust (https://www.rust-lang.org/en-US/install.html)

## Building

To build simply run `cargo build`.

## Testing

Tests are run with Cargo. Unfortunately, due to the environment variable testing in
`database.rs`, tests can only be run on a single thread or you will see some
intermittent errors. To run tests execute:

```
RUST_TEST_THREADS=1 cargo test
```
