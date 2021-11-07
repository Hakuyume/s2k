use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    salt: String,
}

#[derive(Default, Deserialize)]
struct Config {
    pinentry: Option<String>,
    verify: Option<VerifyConfig>,
}

#[derive(Default, Deserialize)]
struct VerifyConfig {
    salt: String,
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
        let key = s2k(verify_config.salt.as_bytes(), passphrase.as_bytes());
        assert_eq!(base64::encode(key), verify_config.key);
    }

    let key = s2k(opts.salt.as_bytes(), passphrase.as_bytes());
    println!("{}", base64::encode(key));
}

fn s2k(salt: &[u8], pin: &[u8]) -> Vec<u8> {
    (0..65536).fold(pin.to_owned(), |key, _| {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(key);
        hasher.finalize().as_slice().to_owned()
    })
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
