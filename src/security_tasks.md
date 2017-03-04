# Iron Vault Security Tasks

This list represents some known security tasks that must be completed.

## Development Tasks
* Have EncryptedStorage take a lambda to determine the encryption key, so we don't have to hold the encryption key open in memory unnecessarily.

## Research Tasks

* Evaluate the source of randomness used by `ring` SystemRandom for each targeted platform.
* Determine if generating a purely random nonce is acceptable for the CHACHA20_POLY1305 algorithm
* How to use `ring pbkdf2::verify` to determine if the password is correct to prevent side-channel attacks
