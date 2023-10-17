/// NIST 800-185 compliant functions.
pub mod nist_800_185 {
    use std::borrow::BorrowMut;

    use byteorder::{BigEndian, WriteBytesExt};

    /// # NIST SP 800-185 2.3.3
    /// The bytepad(X, w) function prepends an encoding of the integer w to an input string X, then pads
    /// the result with zeros until it is a byte string whose length in bytes is a multiple of w.
    /// * `x`: the byte string to pad
    /// * `w`: the rate of the sponge
    /// * `return`: z = encode(`x`) + `x` + (`0` * LCM of length of z and w)
    pub fn byte_pad(input: &mut Vec<u8>, w: u32) -> Vec<u8> {
        let mut z = left_encode(w as u64);
        z.append(input);
        let padlen = w - (z.len() as u32 % w);
        let mut padded = vec![0; padlen as usize];
        z.append(&mut padded);
        z
    }

    /// # NIST SP 800-185 2.3.2
    /// The encode_string function is used to encode bit strings in a way that may be parsed
    /// unambiguously from the beginning of the string.
    /// * `return`: left_encode(len(`s`)) + `s`
    pub fn encode_string(s: &Vec<u8>) -> Vec<u8> {
        let mut encoded = left_encode((s.len() * 8) as u64);
        encoded.append(s.clone().borrow_mut());
        encoded
    }

    /// leftEncode function is used to encode bit strings in a way that may be parsed
    /// unambiguously from the beginning of the string by prepending the encoding of
    /// the length of the string to the beginning of the string.
    /// * `return`: left_encode(len(`s`)) + `s`
    pub fn left_encode(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![1, 0];
        }
        let mut vec = Vec::new();
        vec.write_u64::<BigEndian>(value).unwrap();
        let index = 0;
        //remove leading zeros
        while index < vec.len() && vec[index] == 0 {
            vec.remove(index);
        }
        let mut res = Vec::new();
        res.push(vec.len() as u8);
        res.extend_from_slice(&vec);
        res
    }

    /// rightEncode function is used to encode bit strings in a way that may be parsed
    /// unambiguously from the beginning of the string by prepending the encoding of
    /// the length of the string to the beginning of the string.
    /// * `return`: left_encode(len(s)) + s
    pub fn right_encode(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0, 1];
        }
        let mut b = Vec::new();
        b.write_u64::<BigEndian>(value).unwrap();
        let mut i: u8 = 1;
        while i < 8 && b[i as usize] == 0 {
            i += 1;
        }
        // Prepend number of encoded bytes
        b[0] = 9 - i;
        b[0..(9 - i as usize)].to_vec()
    }
}

pub mod byte_utils {
    /// Aux methods for byte operations.
    use rand::prelude::*;
    use rug::integer::Order::LsfBe;
    use rug::Integer as big;

    /// Gets size number of random bytes.
    /// * `size`: number of bytes requested
    /// * `return: Vec<u8>` of size number of random u8s
    pub fn get_random_bytes(size: u64) -> Vec<u8> {
        let mut rand_bytes = vec![0u8; size as usize];
        thread_rng().fill(&mut rand_bytes[..]);
        rand_bytes
    }

    /// Get a random big with size number of bits
    pub fn get_random_big(size: u64) -> big {
        use rug::rand::RandState;
        use rug::Integer;
        let mut rand = RandState::new();
        let i = Integer::random_bits(size.try_into().unwrap(), &mut rand).into();
        i
    }

    /// XORs byte streams in place using iterators
    /// * `a`: mut references to `Vec<u8>`, will be replaced with result of XOR
    /// * `b`: immut ref to `Vec<u8>`, dropped after function returns
    /// * `Remark`: Probable bottleneck unless impl with SIMD.
    pub fn xor_bytes(a: &mut Vec<u8>, b: &Vec<u8>) {
        assert_eq!(a.len(), b.len());
        a.iter_mut().zip(b.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    }

    ///`return` A string timestamp of current time and date
    /// corresponding to locale on local machine
    pub fn get_date_and_time_as_string() -> String {
        let local = chrono::Local::now();
        local.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    ///Encodes bytes to a hex string and then converts to GMP Integer.
    pub fn bytes_to_big(in_bytes: Vec<u8>) -> big {
        big::from_digits(&in_bytes, LsfBe)
    }

    /// Converts rug::Integer into `Vec<u8>` of form Least significant digit first, with big endian digits.
    pub fn big_to_bytes(in_val: big) -> Vec<u8> {
        big::to_digits(&in_val, LsfBe)
    }
}
