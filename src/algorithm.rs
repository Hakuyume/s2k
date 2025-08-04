use argon2::{Argon2, Params};
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
        argon2: &Argon2<'_>,
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
                let mut key = [0u8; Params::DEFAULT_OUTPUT_LEN];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| digits(&key, 4))
            }
            Algorithm::Argon2id6 => {
                let mut key = [0u8; Params::DEFAULT_OUTPUT_LEN];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| digits(&key, 6))
            }
        }
    }
}

fn digits(key: &[u8], n: u32) -> String {
    let d = 10_u32.pow(n);
    format!(
        "{:01$}",
        key.iter().fold(0_u32, |r, b| ((r << 8) + (*b as u32)) % d),
        n as _,
    )
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

    #[test]
    fn test_argon2id6() {
        assert_eq!(
            super::Algorithm::Argon2id6
                .key(&Argon2::default(), "password", "salt2025")
                .unwrap(),
            "030230",
        );
    }

    #[test]
    fn test_digits() {
        assert_eq!(super::digits(b"key", 6), "038329");
        assert_eq!(super::digits(b"keykeykeykey", 6), "438201");
    }
}
