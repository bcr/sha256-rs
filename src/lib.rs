use std::cmp;
use std::mem;

static K: [u32; 64] = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ];

#[derive(Debug)]
struct Sha256 {
    H: [u32; 8],
    M: [u8; 512 / 8],
    current_block_length_bytes: usize,
    total_data_processed_bytes: usize,
}

impl Sha256 {
    fn new() -> Sha256 {
        let mut return_value = Sha256 {
            H: [0; 8],
            M: [0; 512 / 8],
            current_block_length_bytes: 0,
            total_data_processed_bytes: 0,
        };

        // The current hash value, H, is set to H(0) per the values in FIPS
        // 180-2 §5.3.2. According to that section, “These words were obtained
        // by taking the first thirty-two bits of the fractional parts of the
        // square roots of the first eight prime numbers.”
        return_value.H[0] = 0x6a09e667;
        return_value.H[1] = 0xbb67ae85;
        return_value.H[2] = 0x3c6ef372;
        return_value.H[3] = 0xa54ff53a;
        return_value.H[4] = 0x510e527f;
        return_value.H[5] = 0x9b05688c;
        return_value.H[6] = 0x1f83d9ab;
        return_value.H[7] = 0x5be0cd19;

        return_value
    }

    fn remaining_bytes_in_block(&self) -> usize {
        mem::size_of_val(&self.M) - self.current_block_length_bytes
    }

    fn update(&mut self, data: &[u8]) {
        println!("Update with {}", data.len());
        let mut offset: usize = 0;
        while offset < data.len() {
            let bytes_to_copy = cmp::min(self.remaining_bytes_in_block(), data.len() - offset);

            &self.M[self.current_block_length_bytes..self.current_block_length_bytes + bytes_to_copy].copy_from_slice(&data[offset..(bytes_to_copy + offset)]);

            self.current_block_length_bytes += bytes_to_copy;
            self.total_data_processed_bytes += bytes_to_copy;
            offset += bytes_to_copy;

            if self.remaining_bytes_in_block() == 0 {
                println!("{:?}", self);
                let mut a: u32;
                let mut b: u32;
                let mut c: u32;
                let mut d: u32;
                let mut e: u32;
                let mut f: u32;
                let mut g: u32;
                let mut h: u32;
                let mut t: u32;
                let mut T1: u32;
                let mut T2: u32;
                let mut W : [u32; 64] = [0; 64];

                [a, b, c, d, e, f, g, h] = self.H;

                for t in 0..64 {
                    if t <= 15 {
                        W[t] = (u32::from(self.M[t * 4]) << 24) | (u32::from(self.M[(t * 4) + 1]) << 16) | (u32::from(self.M[(t * 4) + 2]) << 8) | (u32::from(self.M[(t * 4) + 3]));
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

    fn do_final(&mut self) {
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
        self.update(&temp_buffer[0..8])
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
    rotr(x, 2) ^ rotr(x, 13) ^ rotr (x, 22)
}

fn Sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr (x, 25)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut result = Sha256::new();
        result.update("abc".as_bytes());
        result.do_final();
        println!("{:?}", result);
    }
}
