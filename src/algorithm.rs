use base64::prelude::{BASE64_STANDARD, Engine};

#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    strum::Display,
    strum::EnumIter,
    strum::EnumMessage,
    strum::EnumString,
)]
pub(crate) enum Algorithm {
    #[default]
    #[strum(message = "argon2id (256 bits)")]
    Argon2id256,
    #[strum(message = "argon2id (512 bits)")]
    Argon2id512,
    #[strum(message = "argon2id (4 digits)")]
    Argon2id4,
    #[strum(message = "argon2id (6 digits)")]
    Argon2id6,
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
            Algorithm::Argon2id4 => {
                let mut key = [0u8; 2];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| format!("{:04}", u16::from_be_bytes(key) % 10_000))
            }
            Algorithm::Argon2id6 => {
                let mut key = [0u8; 4];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| format!("{:06}", u32::from_be_bytes(key) % 1_000_000))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use argon2::Argon2;

    #[test]
    fn test_argon2id256() {
        assert_eq!(
            super::Algorithm::Argon2id256
                .key(&Argon2::default(), "password", "salt2025")
                .unwrap(),
            "koBvTFMBiW3E247iA86fq//8WZrOb8jUWXstei0b5NY=",
        );
    }
}
