use clap::Parser;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    salt: String,
    #[clap(long)]
    pinentry: Option<String>,
}

fn main() {
    let opts = Opts::parse();

    let pin = pinentry(opts.pinentry.as_ref());

    let key = s2k(opts.salt.as_bytes(), pin.clone().into_bytes());
    println!("{}", base64::encode(key));
}

fn s2k(salt: &[u8], pin: Vec<u8>) -> Vec<u8> {
    (0..65536).fold(pin, |key, _| {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(key);
        hasher.finalize().as_slice().to_owned()
    })
}

fn pinentry<P>(pinentry: Option<P>) -> String
where
    P: AsRef<str>,
{
    let mut child = Command::new(pinentry.as_ref().map_or("pinentry", AsRef::as_ref))
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

    let status = child.wait().unwrap();
    assert!(status.success());

    pin
}
