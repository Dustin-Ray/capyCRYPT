//! Module implementing the guidelines provided in NIST Special Publication 800-185.
pub(crate) mod nist_800_185 {
    use byteorder::{BigEndian, WriteBytesExt};

    /// The bytepad(X, w) function prepends an encoding of the integer w to an input string X, then pads
    /// the result with zeros until it is a byte string whose length in bytes is a multiple of w. See NIST SP 800-185 2.3.3 .
    /// # Arguments:
    /// * `input` - The byte string to pad.
    /// * `w` - The rate of the sponge.
    ///
    /// # Returns:
    /// A byte string z = encode(x) + x + (0 * LCM of length of z and w)
    pub(crate) fn byte_pad(input: &mut Vec<u8>, w: u32) -> Vec<u8> {
        let mut z = left_encode(w as u64);
        z.append(input);
        let padlen = w - (z.len() as u32 % w);
        let mut padded = vec![0; padlen as usize];
        z.append(&mut padded);
        z
    }

    /// The encode_string function is used to encode bit strings in a way that may be parsed
    /// unambiguously from the beginning of the string. See NIST SP 800-185 2.3.2 .
    ///
    /// # Arguments:
    /// * `s` - A reference to a vector of bytes.
    ///
    /// # Returns:
    /// A byte string representing the left-encoded length of `s` concatenated with `s`.
    pub(crate) fn encode_string(s: &Vec<u8>) -> Vec<u8> {
        let mut encoded = left_encode((s.len() * 8) as u64);
        encoded.append(&mut s.clone());
        encoded
    }

    /// # Left Encode
    /// Encodes the input as a vecotr of bytes in a way that can be unambiguously parsed
    /// from the beginning of the string by inserting the length of the byte string before the byte string
    /// representation of the input. See NIST SP 800-185 2.3.1 .
    /// 
    /// # Arguments:
    /// * `value` - The 64-bit unsigned integer to encode.
    /// 
    /// # Returns:
    /// A vector of bytes representing the left-encoded value.
    pub(crate) fn left_encode(value: u64) -> Vec<u8> {
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

    /// # Right Encode
    /// Encodes the input as a byte string in a way that can be unambiguously parsed
    /// from the end of the string by inserting the length of the byte string after the byte string
    /// representation of the input. See NIST SP 800-185 2.3.1 .
    /// 
    /// # Arguments:
    /// * `value` - The 64-bit unsigned integer to encode.
    /// 
    /// # Returns:
    /// A vector of bytes representing the right-encoded value.
    pub(crate) fn right_encode(value: u64) -> Vec<u8> {
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
    use crypto_bigint::Encoding;
    use crypto_bigint::U448;
    use num_bigint::{BigInt as big, RandBigInt};

    /// Aux methods for byte operations.
    use rand::prelude::*;
    use rand::thread_rng;

    use tiny_ed448_goldilocks::curve::field::scalar::Scalar;

    /// Generates and returns a vector of random bytes of the specified size.
    ///
    /// # Arguments:
    /// * `size` - The size of the vector of random bytes to generate.
    ///
    /// # Returns:
    /// A vector of random bytes.
    pub fn get_random_bytes(size: u64) -> Vec<u8> {
        let mut rand_bytes = vec![0u8; size as usize];
        thread_rng().fill(&mut rand_bytes[..]);
        rand_bytes
    }

    /// Generates and returns a random big integer with the specified number of bits.
    ///
    /// # Arguments:
    /// * `bits` - The number of bits for the random big integer.
    ///
    /// # Returns:
    /// A random big integer.
    pub fn get_random_big(bits: usize) -> big {
        let mut rng = thread_rng();

        // The `gen_bigint` method takes the number of bits as argument to generate
        // a random `BigInt`. If you want a non-negative number, make sure the most
        // significant bit is not set, which will effectively give you a number with
        // one bit less than the specified size.
        rng.gen_bigint(bits as u64)
    }

    /// Performs in-place XOR operation on two byte streams using iterators.
    ///
    /// # Arguments:
    /// * `a` - A mutable reference to a vector of bytes to be XORed and replaced with the result.
    /// * `b` - An immutable reference to a vector of bytes.
    ///
    /// # Return:
    /// The result of the XOR operation is stored in the vector referenced by `a`.
    /// 
    /// # Remarks:
    /// This function is a probable bottleneck unless implemented with SIMD.
    pub(crate) fn xor_bytes(a: &mut Vec<u8>, b: &Vec<u8>) {
        assert_eq!(a.len(), b.len());
        a.iter_mut().zip(b.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    }

    /// Returns a string representation of the current local date and time.
    ///
    /// # Returns:
    /// A string timestamp representing the current local time and date corresponding to the locale on the local machine.
    pub(crate) fn get_date_and_time_as_string() -> String {
        let local = chrono::Local::now();
        local.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// Converts a vector of bytes to a Scalar type.
    ///
    /// # Arguments:
    /// * `in_bytes` - A vector of bytes to be converted to a Scalar.
    ///
    /// # Returns:
    /// A Scalar value constructed from the input bytes.
    pub(crate) fn bytes_to_scalar(in_bytes: Vec<u8>) -> Scalar {
        Scalar {
            val: (U448::from_be_slice(&in_bytes)),
        }
    }

    /// Converts a Scalar type to a vector of bytes.
    ///
    /// # Arguments:
    /// * `s` - A reference to a Scalar value to be converted to bytes.
    ///
    /// # Returns:
    /// A vector of bytes representing the Scalar value.
    pub(crate) fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
        s.val.to_be_bytes().to_vec()
    }
}
