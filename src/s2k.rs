use argon2::{Argon2, Params};
use base64::prelude::{BASE64_STANDARD, Engine};

#[derive(strum::EnumCount, strum::EnumMessage, strum::VariantArray)]
pub(crate) enum Algorithm {
    /// argon2id (256 bits)
    Argon2id256,
    /// argon2id (512 bits)
    Argon2id512,
    /// argon2id (4 digits)
    Argon2id4,
    /// argon2id (6 digits)
    Argon2id6,
}

impl Algorithm {
    pub(crate) fn key<P, S>(
        &self,
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
                    .map(|_| encode(&key, &Digits(10), 4))
            }
            Algorithm::Argon2id6 => {
                let mut key = [0u8; Params::DEFAULT_OUTPUT_LEN];
                argon2
                    .hash_password_into(password.as_ref(), salt.as_ref(), &mut key)
                    .map(|_| encode(&key, &Digits(10), 6))
            }
        }
    }
}

fn encode<C>(key: &[u8], chars: &C, count: usize) -> String
where
    C: Chars,
{
    let mut remainder = vec![0; count];

    let n = chars.len();
    for b in key {
        let mut b = *b as u32;
        for r in remainder.iter_mut().rev() {
            let s = (*r << 8) + b;
            b = s / n;
            *r = s % n;
        }
    }

    remainder
        .into_iter()
        .map(|r| chars.get(r).unwrap())
        .collect()
}

trait Chars {
    fn len(&self) -> u32;
    fn get(&self, index: u32) -> Option<char>;
}

struct Digits(u32);
impl Chars for Digits {
    fn len(&self) -> u32 {
        self.0
    }

    fn get(&self, index: u32) -> Option<char> {
        char::from_digit(index, self.0)
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
    fn test_encode() {
        struct U8;
        impl super::Chars for U8 {
            fn len(&self) -> u32 {
                1 << 8
            }

            fn get(&self, index: u32) -> Option<char> {
                u8::try_from(index).ok().map(Into::into)
            }
        }
        assert_eq!(super::encode(b"key", &U8, 6), "\0\0\0key",);

        // python -c 'print(str(int.from_bytes(b"key"))[-6:])'
        assert_eq!(super::encode(b"key", &super::Digits(10), 6), "038329");

        // python -c 'print(bin(int.from_bytes(b"key"))[-6:])'
        assert_eq!(super::encode(b"key", &super::Digits(2), 6), "111001");
        // python -c 'print(oct(int.from_bytes(b"key"))[-6:])'
        assert_eq!(super::encode(b"key", &super::Digits(8), 6), "662571");
        // python -c 'print(hex(int.from_bytes(b"key"))[-6:])'
        assert_eq!(super::encode(b"key", &super::Digits(16), 6), "6b6579");

        // python -c 'import numpy; print(numpy.base_repr(int.from_bytes(b"key"), 23)[-6:])'
        assert_eq!(super::encode(b"key", &super::Digits(23), 6), "123am7");
    }
}
