//! Cryptographic helpers used by zen identity provider.

mod root_secret;

pub(crate) use root_secret::generate_root_secret;
