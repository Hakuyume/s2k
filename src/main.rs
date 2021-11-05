use clap::Parser;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    salt: String,
}

fn main() {
    let opts = Opts::parse();

    let pin = pinentry();

    let key = (0..65536).fold(pin.into_bytes(), |key, _| {
        let mut hasher = Sha256::new();
        hasher.update(opts.salt.as_bytes());
        hasher.update(key);
        hasher.finalize().as_slice().to_owned()
    });
    println!("{}", base64::encode(key));
}

fn pinentry() -> String {
    let mut child = Command::new("pinentry")
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
