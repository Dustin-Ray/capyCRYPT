use std::ops::{Div, Mul, Sub};

use crypto_bigint::{
    const_residue, impl_modulus,
    modular::constant_mod::ResidueParams,
    subtle::{Choice, ConstantTimeEq},
    Encoding, NonZero, U448,
};

pub const R_448: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";

pub const R_2: &str = "049b9b60e3539257c1b195d97af32c4b88ea18590d66de235ee4d838ae17cf72a3c47c441a9cc14be4d070af2052bcb7f823b7293402a939";

impl_modulus!(
    Modulus,
    U448,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
);

#[derive(Debug, Clone, Copy)]
pub struct Scalar {
    pub val: U448,
}

impl Scalar {
    /// a + b mod p
    pub fn add_mod(&self, rhs: &Self) -> Self {
        Self::from(self.val.add_mod(&rhs.val, &Modulus::MODULUS))
    }

    // a - b mod p
    pub fn sub_mod(&self, rhs: &Self) -> Self {
        Self::from(self.val.sub_mod(&rhs.val, &Modulus::MODULUS))
    }

    /// Divides a scalar by four without reducing mod p
    /// This is used in the 2-isogeny when mapping points from Ed448-Goldilocks
    /// to Twisted-Goldilocks
    pub fn div_four(&mut self) {
        self.val = self.val.div(&NonZero::new(U448::from(4_u64)).unwrap());
    }

    pub fn from<T: Into<U448>>(val: T) -> Self {
        Scalar { val: val.into() }
    }

    pub fn invert(&mut self) {
        self.val.inv_mod(&U448::from_be_hex(R_448));
    }

    /// Performs a fixed-time modular multiplication of two `Scalar` values.
    ///
    /// This method multiplies the current `Scalar` instance (`self`) with another `Scalar` (`rhs`)
    /// and returns the product modulo a predefined modulus (`Modulus`). It uses fixed-time
    /// Montgomery reduction algorithm in the `crypto-bigint` backend for the multiplication, which is
    /// crucial for cryptographic applications to ensure both security and efficiency.
    ///
    /// Montgomery reduction is a method used in modular arithmetic that allows for efficient
    /// computation of modular multiplication and reduction without explicitly performing division.
    /// The algorithm operates in a way that is independent of the values of the operands, thereby
    /// ensuring fixed-time execution, which is vital for protecting against timing attacks in
    /// cryptographic operations.
    ///
    /// ## Arguments
    ///
    /// * `rhs`: A reference to the `Scalar` instance to be multiplied with `self`.
    ///
    /// ## Returns
    ///
    /// A new `Scalar` instance representing the result of the modular multiplication.
    ///
    pub fn mul_mod(&self, rhs: &Scalar) -> Scalar {
        let self_val: U448 = self.val;
        let rhs_val: U448 = rhs.val;
        let a = const_residue!(self_val, Modulus);
        let b = const_residue!(rhs_val, Modulus);
        Scalar {
            val: a.mul(&b).retrieve(),
        }
    }

    // this is a bummer, will fix asap
    pub fn mul_mod_r(&self, rhs: &Scalar) -> Scalar {
        impl_modulus!(
            R,
            U448,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        );
        let self_val: U448 = self.val;
        let rhs_val: U448 = rhs.val;
        let a = const_residue!(self_val, R);
        let b = const_residue!(rhs_val, R);
        Scalar {
            val: a.mul(&b).retrieve(),
        }
    }

    /// Converts a scalar value from radix 256 to radix 16. Borrowed from the dalek authors.
    ///
    /// This function takes a scalar value (`self`) and converts it from a byte representation
    /// (radix 256) to a representation in radix 16 (nibbles). The output is an array of `i8` values
    /// with a length of 113, where each element represents a nibble in radix 16.
    ///
    /// # Details
    ///
    /// The scalar value is first converted to its little-endian byte representation. Each byte
    /// contains two nibbles (half-bytes), which are extracted separately as the top and bottom
    /// halves of the byte. These nibbles are then re-centered to have values in the range [-8, 8),
    /// which is achieved by adjusting each nibble based on a carry-over from its predecessor.
    ///
    /// The conversion process involves two main steps:
    ///
    /// 1. Radix conversion: Each byte of the scalar is split into two nibbles (4 bits each).
    ///    The bottom half (`bot_half`) and the top half (`top_half`) of each byte are extracted
    ///    and stored as separate elements in the output array.
    ///
    /// 2. Re-centering coefficients: After the initial conversion, the coefficients (nibbles)
    ///    are in the range [0, 15]. They are re-centered to be within [-8, 8) by calculating a
    ///    carry value and adjusting the nibbles accordingly. This process ensures that each
    ///    coefficient is within the desired range, while maintaining the overall value of the
    ///    scalar.  It reduces the number of required operations compared to binary,
    ///    while still being more efficient to handle than byte-wise operations in certain
    ///    cryptographic algorithms.
    ///
    /// # Returns
    ///
    /// An array of 113 `i8` elements, each representing a nibble of the original scalar in radix 16.
    /// ```
    pub(crate) fn to_radix_16(self) -> [i8; 113] {
        let bytes = self.val.to_le_bytes();
        let mut output = [0i8; 113];

        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        #[inline(always)]
        fn bot_half(x: u8) -> u8 {
            x & 15
        }
        #[inline(always)]
        fn top_half(x: u8) -> u8 {
            (x >> 4) & 15
        }

        // radix-16 conversion
        for i in 0..56 {
            output[2 * i] = bot_half(bytes[i]) as i8;
            output[2 * i + 1] = top_half(bytes[i]) as i8;
        }

        // re-center coefficients to be between [-8, 8)
        for i in 0..112 {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }

        output
    }

    /// Adapated from:
    /// https://github.com/crate-crypto/Ed448-Goldilocks/blob/master/src/field/scalar.rs
    /// to work over 64-bit word sizes
    ///
    /// ### REMARK:
    /// Works but I make no claims of fixed-time. `mul_mod` uses
    /// the crypto-bigint montgomery reduce backend and is definitely the correct choice.
    /// allow(dead_code) because I think this function is cool and worth hanging on to for now.
    #[allow(dead_code)]
    fn montgomery_multiply_64(&self, montgomery_factor: &U448) -> Self {
        let mut result = U448::ZERO;
        let mut carry = 0;

        // Loop over the limbs of x and y, multiplying and adding to get the result.
        for i in 0..self.val.as_limbs().len() {
            let mut chain: u128 = 0; // Using u128 for the chain to handle potential overflow.

            // Perform the multiplication-addition for each limb.
            for (j, &ylimb) in self.val.as_limbs().iter().enumerate() {
                chain += u128::from(self.val.as_limbs()[i]) * u128::from(ylimb)
                    + u128::from(result.as_limbs()[j]);
                result.as_limbs_mut()[j] = crypto_bigint::Limb(chain as u64);
                chain >>= 64;
            }

            let saved = chain as u64;
            // Calculate the multiplicand for the Montgomery operation.
            let multiplicand = result.as_limbs()[0].wrapping_mul(montgomery_factor.as_limbs()[0]);

            chain = 0;
            for (j, &mlimb) in Modulus::MODULUS.as_limbs().iter().enumerate() {
                chain += (u128::from(multiplicand)) * u128::from(mlimb)
                    + u128::from(result.as_limbs()[j]);
                if j > 0 {
                    result.as_limbs_mut()[j - 1] = crypto_bigint::Limb(chain as u64);
                }
                chain >>= 64;
            }

            // Add the carried value from previous iteration and the saved value.
            chain += (saved as u128) + (carry as u128);
            result.as_limbs_mut()[self.val.as_limbs().len() - 1] =
                crypto_bigint::Limb(chain as u64);
            carry = (chain >> 64) as u64;
        }

        result = result.sub_mod(&Modulus::MODULUS, &Modulus::MODULUS);
        Scalar::from(result)
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.val.to_be_bytes().ct_eq(&other.val.to_be_bytes())
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Scalar) -> bool {
        self.ct_eq(other).into()
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Self::Output {
        self.mul_mod(&rhs)
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Scalar) -> Self::Output {
        self.sub_mod(&rhs)
    }
}

#[test]
fn test_div_rem() {
    let a = U448::from(8_u64);
    let b = NonZero::new(U448::from(4_u64)).unwrap();
    let res = a.div_rem(&b);
    // 8 / 4 = 2 with no remainder
    assert!(res.0 == U448::from(2_u64));
    assert!(res.1 == U448::ZERO);
}

// TODO: test scalar mul
