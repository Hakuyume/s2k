use base64::prelude::{BASE64_STANDARD, Engine};
use sha2::{Sha256, digest};

#[derive(
    Clone, Copy, PartialEq, strum::Display, strum::EnumIter, strum::EnumMessage, strum::EnumString,
)]
pub(crate) enum Algorithm {
    #[strum(message = "argon2id (256 bits)")]
    Argon2id256,
    #[strum(message = "argon2id (512 bits)")]
    Argon2id512,
    #[strum(message = "argon2id (6 digits)")]
    Argon2id6,
    #[strum(message = "s2k (SHA256)")]
    S2kSha256,
}

impl Algorithm {
    pub(crate) fn key<P, S>(
        self,
        argon2: &argon2::Argon2<'_>,
        password: P,
        salt: S,
    ) -> Result<String, argon2::Error>
    where
        P: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        match self {
            Self::Argon2id256 => {
                let mut key = [0u8; 32];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| BASE64_STANDARD.encode(key))
            }
            Algorithm::Argon2id512 => {
                let mut key = [0u8; 64];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| BASE64_STANDARD.encode(key))
            }
            Algorithm::Argon2id6 => {
                let mut key = [0u8; 4];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| format!("{:06}", u32::from_be_bytes(key) % 1_000_000))
            }
            Algorithm::S2kSha256 => {
                Ok(BASE64_STANDARD.encode(s2k::<Sha256>(salt.as_ref(), password.as_ref(), 65536)))
            }
        }
    }
}

fn s2k<D>(salt: &[u8], passphrase: &[u8], count: usize) -> digest::Output<D>
where
    D: digest::Digest,
{
    let mut hasher = D::new();
    for &b in salt.iter().chain(passphrase).cycle().take(count) {
        hasher.update([b]);
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_s2k() {
        // gpg --cipher-algo AES256 --s2k-count 65536 --s2k-digest SHA256 --s2k-mode 3 --symmetric <FILE>
        // gpg --list-packets --show-session-key <FILE>.gpg
        assert_eq!(
            super::s2k::<Sha256>(&hex!("3109800B39D9C9D6"), b"passphrase", 65536).as_slice(),
            hex!("4892EE6C021A36201DE80C625C7F2B654C3AAC4578308F03A22B67BF25E893F6"),
        );
    }
}
