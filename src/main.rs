use std::io::{self, Read};

use sha256::Sha256;

fn main() {
    let mut sha256 = Sha256::new();
    sha256.update_other(io::stdin().bytes().map(|x| x.unwrap()));
    println!("{:02x?}", sha256.do_final());
}
