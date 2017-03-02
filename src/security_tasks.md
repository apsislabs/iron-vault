# Iron Vault Security Tasks

This list represents some known security tasks that must be completed.

## Open Tasks

* Evaluate the source of randomness used by `ring` SystemRandom for each targeted platform.
* Determine if generating a purely random nonce is acceptable for the CHACHA20_POLY1305 algorithm
