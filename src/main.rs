use clap::Parser;
use serde::Deserialize;
use sha2::{digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    salt: String,
    #[clap(default_value = "65536", long)]
    count: usize,
}

#[derive(Default, Deserialize)]
struct Config {
    pinentry: Option<String>,
    verify: Option<VerifyConfig>,
}

#[derive(Default, Deserialize)]
struct VerifyConfig {
    salt: String,
    count: usize,
    key: String,
}

fn main() {
    let opts = Opts::parse();

    let config = if let Some(config_file) = dirs::config_dir()
        .map(|config_dir| config_dir.join("s2k.toml"))
        .filter(|config_file| config_file.exists())
    {
        let mut buf = Vec::new();
        File::open(&config_file)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        toml::from_slice(&buf).unwrap()
    } else {
        Config::default()
    };

    let passphrase = pinentry(config.pinentry.as_ref());

    if let Some(verify_config) = &config.verify {
        let key = s2k::<Sha256>(
            verify_config.salt.as_bytes(),
            passphrase.as_bytes(),
            verify_config.count,
        );
        assert_eq!(base64::encode(key), verify_config.key);
    }

    let key = s2k::<Sha256>(opts.salt.as_bytes(), passphrase.as_bytes(), opts.count);
    println!("{}", base64::encode(key));
}

fn pinentry<P>(pinentry: Option<P>) -> String
where
    P: AsRef<OsStr>,
{
    let mut child = Command::new(pinentry.as_ref().map_or("pinentry".as_ref(), AsRef::as_ref))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(&mut stdin, "GETPIN").unwrap();
    stdin.flush().unwrap();

    let pin = stdout
        .lines()
        .find_map(|line| line.unwrap().strip_prefix("D ").map(str::to_owned))
        .unwrap();

    writeln!(&mut stdin, "BYE").unwrap();
    stdin.flush().unwrap();

    child.wait().unwrap();

    pin
}

fn s2k<D>(salt: &[u8], passphrase: &[u8], count: usize) -> digest::Output<D>
where
    D: digest::Digest,
{
    let mut hasher = D::new();
    for &b in salt.iter().chain(passphrase).cycle().take(count) {
        hasher.update(&[b]);
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
            &hex!("4892EE6C021A36201DE80C625C7F2B654C3AAC4578308F03A22B67BF25E893F6"),
        );
    }
}
