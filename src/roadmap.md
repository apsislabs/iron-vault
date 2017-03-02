# Iron Vault Roadmap

This document lists planned upcoming development work for the main line of the
project by the core contributors. This does not represent the _only_ work that
will happen on Iron Vault (for example we will accept pull requests outside the
scope of the roadmap).

## Version 0.1.0

This is the version to capture the initial development efforts and will not be released.

## Version 0.2.0

The goal of Version 0.2.0 is to develop `vault_core` to the point that it could
reasonably be used for an incredibly bare-bones implementation of Iron Vault. As
part of this milestone `iv` will be developed only to the extent necessary
to demonstrate the use of `vault_core`, and will not be considered part of the
Version 0.2.0 release.

### Milestone 1 - Read and Write Encrypted Files
**In Progress**
* **Completed** Read and Write to simple encrypted files
* **In Progress** Generate and store an encryption key file
* Store a "encryption data" file with dummy data using the encryption key.
* Use a key derivation function to encrypt the encryption key file with a master password

### Milestone 2 - Store And Retrieve Named Passwords

### Milestone 3 - Store And Retrieve Arbitrary Metadata for Named Passwords

### Milestone 4 - Store Index for Passwords

### Milestone 5 - Hold Database Unlocked

### Future Milestones TBD

## Version 0.3.0

The goal of Version 0.3.0 is to develop `iv` to be a bare-bones command line
application that can effectively store and retrieve passwords.
