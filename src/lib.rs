use std::cmp;
use std::num::Wrapping;
use std::mem;

static K: [Wrapping<u32>; 64] = [ Wrapping(0x428a2f98), Wrapping(0x71374491), Wrapping(0xb5c0fbcf), Wrapping(0xe9b5dba5),
                        Wrapping(0x3956c25b), Wrapping(0x59f111f1), Wrapping(0x923f82a4), Wrapping(0xab1c5ed5),
                        Wrapping(0xd807aa98), Wrapping(0x12835b01), Wrapping(0x243185be), Wrapping(0x550c7dc3),
                        Wrapping(0x72be5d74), Wrapping(0x80deb1fe), Wrapping(0x9bdc06a7), Wrapping(0xc19bf174),
                        Wrapping(0xe49b69c1), Wrapping(0xefbe4786), Wrapping(0x0fc19dc6), Wrapping(0x240ca1cc),
                        Wrapping(0x2de92c6f), Wrapping(0x4a7484aa), Wrapping(0x5cb0a9dc), Wrapping(0x76f988da),
                        Wrapping(0x983e5152), Wrapping(0xa831c66d), Wrapping(0xb00327c8), Wrapping(0xbf597fc7),
                        Wrapping(0xc6e00bf3), Wrapping(0xd5a79147), Wrapping(0x06ca6351), Wrapping(0x14292967),
                        Wrapping(0x27b70a85), Wrapping(0x2e1b2138), Wrapping(0x4d2c6dfc), Wrapping(0x53380d13),
                        Wrapping(0x650a7354), Wrapping(0x766a0abb), Wrapping(0x81c2c92e), Wrapping(0x92722c85),
                        Wrapping(0xa2bfe8a1), Wrapping(0xa81a664b), Wrapping(0xc24b8b70), Wrapping(0xc76c51a3),
                        Wrapping(0xd192e819), Wrapping(0xd6990624), Wrapping(0xf40e3585), Wrapping(0x106aa070),
                        Wrapping(0x19a4c116), Wrapping(0x1e376c08), Wrapping(0x2748774c), Wrapping(0x34b0bcb5),
                        Wrapping(0x391c0cb3), Wrapping(0x4ed8aa4a), Wrapping(0x5b9cca4f), Wrapping(0x682e6ff3),
                        Wrapping(0x748f82ee), Wrapping(0x78a5636f), Wrapping(0x84c87814), Wrapping(0x8cc70208),
                        Wrapping(0x90befffa), Wrapping(0xa4506ceb), Wrapping(0xbef9a3f7), Wrapping(0xc67178f2) ];

#[derive(Debug)]
struct Sha256 {
    H: [Wrapping<u32>; 8],
    M: [u8; 512 / 8],
    current_block_length_bytes: usize,
    total_data_processed_bytes: usize,
}

impl Sha256 {
    fn new() -> Sha256 {
        let mut return_value = Sha256 {
            H: [Wrapping(0u32); 8],
            M: [0; 512 / 8],
            current_block_length_bytes: 0,
            total_data_processed_bytes: 0,
        };

        // The current hash value, H, is set to H(0) per the values in FIPS
        // 180-2 §5.3.2. According to that section, “These words were obtained
        // by taking the first thirty-two bits of the fractional parts of the
        // square roots of the first eight prime numbers.”
        return_value.H[0] = Wrapping(0x6a09e667);
        return_value.H[1] = Wrapping(0xbb67ae85);
        return_value.H[2] = Wrapping(0x3c6ef372);
        return_value.H[3] = Wrapping(0xa54ff53a);
        return_value.H[4] = Wrapping(0x510e527f);
        return_value.H[5] = Wrapping(0x9b05688c);
        return_value.H[6] = Wrapping(0x1f83d9ab);
        return_value.H[7] = Wrapping(0x5be0cd19);

        return_value
    }

    fn remaining_bytes_in_block(&self) -> usize {
        mem::size_of_val(&self.M) - self.current_block_length_bytes
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset: usize = 0;
        while offset < data.len() {
            let bytes_to_copy = cmp::min(self.remaining_bytes_in_block(), data.len() - offset);

            &self.M[self.current_block_length_bytes..self.current_block_length_bytes + bytes_to_copy].copy_from_slice(&data[offset..(bytes_to_copy + offset)]);

            self.current_block_length_bytes += bytes_to_copy;
            self.total_data_processed_bytes += bytes_to_copy;
            offset += bytes_to_copy;

            if self.remaining_bytes_in_block() == 0 {
                let mut a = Wrapping(0u32);
                let mut b = Wrapping(0u32);
                let mut c = Wrapping(0u32);
                let mut d = Wrapping(0u32);
                let mut e = Wrapping(0u32);
                let mut f = Wrapping(0u32);
                let mut g = Wrapping(0u32);
                let mut h = Wrapping(0u32);
                let mut t = Wrapping(0u32);
                let mut T1 = Wrapping(0u32);
                let mut T2 = Wrapping(0u32);
                let mut W : [Wrapping<u32>; 64] = [Wrapping(0u32); 64];

                [a, b, c, d, e, f, g, h] = self.H;

                for t in 0..64 {
                    if t <= 15 {
                        W[t] = Wrapping((u32::from(self.M[t * 4]) << 24) | (u32::from(self.M[(t * 4) + 1]) << 16) | (u32::from(self.M[(t * 4) + 2]) << 8) | (u32::from(self.M[(t * 4) + 3])));
                    } else {
                        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
                    }

                    T1 = h + Sigma1(e) + Ch(e,f,g)+ K[t]+ W[t];
                    T2 = Sigma0(a) + Maj (a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2;
                }

                self.H[0] += a;
                self.H[1] += b;
                self.H[2] += c;
                self.H[3] += d;
                self.H[4] += e;
                self.H[5] += f;
                self.H[6] += g;
                self.H[7] += h;

                self.current_block_length_bytes = 0;
            }
        }
    }

    fn do_final(&mut self) -> [u8; 32] {
        let total_data_processed_bits = self.total_data_processed_bytes * 8;
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
        self.update(&temp_buffer[0..self.remaining_bytes_in_block() - 8]);

        temp_buffer[0] = ((total_data_processed_bits >> 56) & 0x0ff) as u8;
        temp_buffer[1] = ((total_data_processed_bits >> 48) & 0x0ff) as u8;
        temp_buffer[2] = ((total_data_processed_bits >> 40) & 0x0ff) as u8;
        temp_buffer[3] = ((total_data_processed_bits >> 32) & 0x0ff) as u8;
        temp_buffer[4] = ((total_data_processed_bits >> 24) & 0x0ff) as u8;
        temp_buffer[5] = ((total_data_processed_bits >> 16) & 0x0ff) as u8;
        temp_buffer[6] = ((total_data_processed_bits >>  8) & 0x0ff) as u8;
        temp_buffer[7] = ((total_data_processed_bits      ) & 0x0ff) as u8;
        self.update(&temp_buffer[0..8]);

        let mut return_value: [u8; 32] = [0; 32];

        for counter in 0..8 {
            return_value[(counter * 4) + 0] = ((self.H[counter].0 >> 24) & 0x0ff) as u8;
            return_value[(counter * 4) + 1] = ((self.H[counter].0 >> 16) & 0x0ff) as u8;
            return_value[(counter * 4) + 2] = ((self.H[counter].0 >>  8) & 0x0ff) as u8;
            return_value[(counter * 4) + 3] = ((self.H[counter].0) & 0x0ff) as u8;
        }

        return_value
    }
}

fn Ch(x: Wrapping<u32>, y: Wrapping<u32>, z: Wrapping<u32>) -> Wrapping<u32> {
    (x & y) ^ (!x & z)
}

fn Maj(x: Wrapping<u32>, y: Wrapping<u32>, z: Wrapping<u32>) -> Wrapping<u32> {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr(x: u32, n: u8) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn sigma0(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 7) ^ rotr(x.0, 18) ^ (x.0 >> 3))
}

fn sigma1(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 17) ^ rotr(x.0, 19) ^ (x.0 >> 10))
}

fn Sigma0(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 2) ^ rotr(x.0, 13) ^ rotr (x.0, 22))
}

fn Sigma1(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 6) ^ rotr(x.0, 11) ^ rotr (x.0, 25))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut sha256 = Sha256::new();
        sha256.update("abc".as_bytes());
        let actual = sha256.do_final();
        let expected: [u8; 32] = [  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad];
        assert_eq!(actual, expected);
    }
}
