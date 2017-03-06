# Iron Vault Roadmap

This document lists planned upcoming development work for the main line of the project by the core contributors. This does not represent the _only_ work that will happen on Iron Vault (for example we will accept pull requests outside the scope of the roadmap).

## Version 0.1.0

This is the version to capture the initial development efforts and will not be released.

## Version 0.2.0

The goal of version 0.2.0 is to develop `vault_core` to the point that it could reasonably be used for an incredibly bare-bones implementation of Iron Vault. As part of this milestone `iv` will be developed only to the extent necessary to demonstrate the use of `vault_core`, and will not be considered part of the version 0.2.0 release.

### Milestone 1 - Read and Write Encrypted Files
**Completed**
* **Completed** Read and Write to simple encrypted files
* **Completed** Generate and store an encryption key file
* **Completed** Use a key derivation function to encrypt the encryption key file with a master password
* **Completed** Store a "encryption data" file with dummy data using the encryption key.

### Milestone 2 - Store And Retrieve Named Passwords
**In Progress**
* **Completed** Create Record structure.
* **Completed** Serialize Record structure to JSON.
* **Completed** Deserialized Record structure from JSON.
* Update Database to be able to store new Password.
* Update Database to be able to retrieve Password.

### Milestone 3 - Store And Retrieve Arbitrary Metadata for Named Passwords
* Update record to be able to easily fetch metadata attributes

## Milestone 4 - Clean up database implementation
* Clean up database implementation
* Clean up publicly exposed mods

### Future Milestones TBD

## Version 0.3.0

The goal of version 0.3.0 is to develop `iv` to be a bare-bones command line application that can effectively store and retrieve passwords.

## Version 0.4.0

The goal of version of 0.4.0 is to begin add some very basic interface quality of life improvements. Details can be seen in the milestone below, but this version should include features like search, or holding the database open for a short period of time, and copy to clipboard

### Milestone 1 - Store Index for Passwords and Search

### Milestone 2 - Hold Database Unlocked

### Milestone 3 - Copy to clipboard
