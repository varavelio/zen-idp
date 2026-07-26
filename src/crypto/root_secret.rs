use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

/// Number of random bytes used to create a root secret.
///
/// Thirty-two bytes provide 256 bits of entropy while keeping the generated
/// environment variable reasonably compact after Base64url encoding.
const ROOT_SECRET_LENGTH: usize = 32;

/// Generates a cryptographically secure root secret.
///
/// The secret is created from operating-system randomness and encoded as
/// unpadded Base64url, making it safe to pass through environment variables
/// and command-line output without introducing characters that commonly need
/// shell escaping. The returned value is zeroized when it is dropped.
///
/// # Errors
///
/// Returns [`getrandom::Error`] if the operating system cannot provide secure
/// random bytes.
pub(crate) fn generate_root_secret() -> Result<Zeroizing<String>, getrandom::Error> {
    let mut bytes = Zeroizing::new([0_u8; ROOT_SECRET_LENGTH]);
    getrandom::fill(bytes.as_mut())?;

    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::{ROOT_SECRET_LENGTH, generate_root_secret};

    #[test]
    fn generated_secret_has_canonical_length_and_encoding() {
        let result = generate_root_secret();
        let Ok(secret) = result else {
            panic!("operating system randomness should be available");
        };
        let decoded = URL_SAFE_NO_PAD.decode(secret.as_bytes());
        let Ok(decoded) = decoded else {
            panic!("generated secret should be unpadded Base64url");
        };

        assert_eq!(decoded.len(), ROOT_SECRET_LENGTH);
        assert!(!secret.contains('='));
    }
}
