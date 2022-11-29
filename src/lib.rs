#![allow(non_snake_case)]

use std::io::{Read, Result};
use std::mem;
use std::num::Wrapping;

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug)]
pub struct Sha256 {
    H: [u32; 8],
    M: [u8; 512 / 8],
    current_block_length_bytes: usize,
    total_data_processed_bytes: usize,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        let mut return_value = Sha256 {
            H: [0u32; 8],
            M: [0; 512 / 8],
            current_block_length_bytes: 0,
            total_data_processed_bytes: 0,
        };

        return_value.init();

        return_value
    }

    fn remaining_bytes_in_block(&self) -> usize {
        mem::size_of_val(&self.M) - self.current_block_length_bytes
    }

    fn init(&mut self) {
        // The current hash value, H, is set to H(0) per the values in FIPS
        // 180-2 §5.3.2. According to that section, “These words were obtained
        // by taking the first thirty-two bits of the fractional parts of the
        // square roots of the first eight prime numbers.”
        self.H[0] = 0x6a09e667;
        self.H[1] = 0xbb67ae85;
        self.H[2] = 0x3c6ef372;
        self.H[3] = 0xa54ff53a;
        self.H[4] = 0x510e527f;
        self.H[5] = 0x9b05688c;
        self.H[6] = 0x1f83d9ab;
        self.H[7] = 0x5be0cd19;

        self.current_block_length_bytes = 0;
        self.total_data_processed_bytes = 0;
    }

    fn process_block(&mut self) {
        let mut a: u32;
        let mut b: u32;
        let mut c: u32;
        let mut d: u32;
        let mut e: u32;
        let mut f: u32;
        let mut g: u32;
        let mut h: u32;
        let mut T1: u32;
        let mut T2: u32;
        let mut W: [u32; 64] = [0u32; 64];

        [a, b, c, d, e, f, g, h] = self.H;

        for t in 0..64 {
            if t <= 15 {
                let bytes: [u8; 4] = self.M[t * 4..(t * 4) + 4].try_into().unwrap();
                W[t] = u32::from_be_bytes(bytes);
            } else {
                W[t] = (Wrapping(sigma1(W[t - 2]))
                    + Wrapping(W[t - 7])
                    + Wrapping(sigma0(W[t - 15]))
                    + Wrapping(W[t - 16]))
                .0;
            }

            T1 = (Wrapping(h)
                + Wrapping(Sigma1(e))
                + Wrapping(Ch(e, f, g))
                + Wrapping(K[t])
                + Wrapping(W[t]))
            .0;
            T2 = (Wrapping(Sigma0(a)) + Wrapping(Maj(a, b, c))).0;
            h = g;
            g = f;
            f = e;
            e = (Wrapping(d) + Wrapping(T1)).0;
            d = c;
            c = b;
            b = a;
            a = (Wrapping(T1) + Wrapping(T2)).0;
        }

        self.H = self
            .H
            .iter()
            .map(|x| Wrapping(*x))
            .zip([a, b, c, d, e, f, g, h].iter().map(|x| Wrapping(*x)))
            .map(|(x, y)| x + y)
            .map(|x| x.0)
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
    }

    pub fn update_from_reader(&mut self, reader: &mut dyn Read) -> Result<usize> {
        let mut total_bytes_read: usize = 0;
        loop {
            let bytes_read = reader.read(&mut self.M[self.current_block_length_bytes..])?;

            if bytes_read == 0 {
                break;
            }

            self.current_block_length_bytes += bytes_read;
            self.total_data_processed_bytes += bytes_read;
            total_bytes_read += bytes_read;
            if self.remaining_bytes_in_block() == 0 {
                self.process_block();
                self.current_block_length_bytes = 0;
            }
        }
        Ok(total_bytes_read)
    }

    pub fn update<'a, T>(&mut self, data: T)
    where
        T: IntoIterator<Item = &'a u8>,
    {
        self.update_other(data.into_iter().map(|x| *x));
    }

    pub fn update_other<T>(&mut self, data: T)
    where
        T: IntoIterator<Item = u8>,
    {
        for this_byte in data {
            self.M[self.current_block_length_bytes] = this_byte;
            self.current_block_length_bytes += 1;
            self.total_data_processed_bytes += 1;
            if self.remaining_bytes_in_block() == 0 {
                self.process_block();
                self.current_block_length_bytes = 0;
            }
        }
    }

    pub fn do_final(&mut self) -> [u8; 32] {
        let total_data_processed_bits = (self.total_data_processed_bytes * 8).to_be_bytes();
        let mut temp_buffer: [u8; 512 / 8] = [0; 512 / 8];

        // We need to jam a single 1 bit, followed by some number of 0 bits
        // followed by 64 bits of the length (in bits) of the data that has
        // been digested (from FIPS 180-2 §5.1.1).
        temp_buffer[0] = 0x80;
        self.update(&temp_buffer[0..1]);
        temp_buffer[0] = 0;

        if self.remaining_bytes_in_block() < 8 {
            self.update(&temp_buffer[0..self.remaining_bytes_in_block()]);
        }
        self.update(
            &temp_buffer[0..self.remaining_bytes_in_block() - total_data_processed_bits.len()],
        );

        self.update(&total_data_processed_bits);

        let mut return_value: [u8; 32] = [0; 32];

        for counter in 0..8 {
            return_value[(counter * 4)..((counter * 4) + 4)]
                .copy_from_slice(&self.H[counter].to_be_bytes());
        }

        return_value
    }
}

fn Ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn Maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr(x: u32, n: u8) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

fn Sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn Sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-2 §B.1, hashing the string "abc"
    #[test]
    fn test_b1() {
        let mut sha256 = Sha256::new();
        sha256.update("abc".as_bytes());
        let actual = sha256.do_final();
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(actual, expected);
    }

    // FIPS 180-2 §B.2, hashing the string "abcdbc..."
    #[test]
    fn test_b2() {
        let mut sha256 = Sha256::new();
        sha256.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
        let actual = sha256.do_final();
        let expected: [u8; 32] = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(actual, expected);
    }

    // FIPS 180-2 §B.3, hashing the byte ’a’ 1,000,000 times
    #[test]
    fn test_b3() {
        let mut sha256 = Sha256::new();
        sha256.update_other((0..1_000_000).map(|_| b'a'));
        let actual = sha256.do_final();
        let expected: [u8; 32] = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];
        assert_eq!(actual, expected);
    }
}
