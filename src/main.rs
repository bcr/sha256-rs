use std::io;

use sha256::Sha256;

fn main() {
    let mut sha256 = Sha256::new();
    sha256.update_from_reader(&mut io::stdin().lock()).unwrap();
    println!("{:02x?}", sha256.do_final());
}
