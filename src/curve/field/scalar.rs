use std::ops::{Div, Mul};

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
    // a + b mod p
    pub fn add(&self, rhs: &Self) -> Self {
        Self::from_uint(self.val.add_mod(&rhs.val, &Modulus::MODULUS))
    }

    /// Divides a scalar by four without reducing mod p
    /// This is used in the 2-isogeny when mapping points from Ed448-Goldilocks
    /// to Twisted-Goldilocks
    pub fn div_four(&mut self) {
        self.val = self.val.div(&NonZero::new(U448::from(4_u64)).unwrap());
    }

    pub fn invert(&mut self) {
        self.val.inv_mod(&U448::from_be_hex(R_448));
    }

    pub fn mul_mod(&self, rhs: &Scalar) -> Scalar {
        let self_val: U448 = self.val;
        let rhs_val: U448 = rhs.val;
        let a = const_residue!(self_val, Modulus);
        let b = const_residue!(rhs_val, Modulus);
        Scalar {
            val: a.mul(&b).retrieve(),
        }
    }

    pub fn from(val: u64) -> Self {
        Scalar {
            val: U448::from(val),
        }
    }

    pub fn from_uint(val: U448) -> Self {
        Scalar { val }
    }

    pub(crate) fn to_radix_16(&self) -> [i8; 113] {
        let bytes = self.val.to_le_bytes(); // Convert the 7 u64 limbs to a 56-byte array
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

    /// adapated from:
    ///  https://github.com/crate-crypto/Ed448-Goldilocks/blob/master/src/field/scalar.rs
    /// to work over 64-bit word sizes
    pub fn montgomery_multiply_64(&self, montgomery_factor: &U448) -> Self {
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
        Scalar::from_uint(result)
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
        let unreduced = self.montgomery_multiply_64(&rhs.val);
        unreduced.montgomery_multiply_64(&U448::from_be_hex(R_2))
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

#[test]
fn test_mul() {
    let a = Scalar::from_uint(U448::from([
        0xffb823a3c96a3c35,
        0x7f8ed27d087b8fb9,
        0x1d9ac30a74d65764,
        0xc0be082ea8cb0ae8,
        0xa8fa552b2aae8688,
        0x2c3dc27347cf8cac,
        0x3b089f071e63e807,
    ]));

    let b = Scalar::from_uint(U448::from([
        0xd8bedc42686eb329,
        0xe416b89917aa6d9b,
        0x1e30b38b188c6b1a,
        0xd099595bbc343bcb,
        0x1adaa0e724e8d499,
        0x8e59b3080a92de2d,
        0xcae1cb6816c5450a,
    ]));

    let c = Scalar::from_uint(U448::from([
        0xa18d010a1f5b3197,
        0x994c9c2b6abd26f5,
        0x08a3a0e436a14920,
        0x74e9335f07bcd931,
        0xf2d89c1eb9036ff6,
        0x203d424bfccd61b3,
        0x4ca389ed31e055c1,
    ]));

    let product_mod_p = a.val.mul_wide(&b.val);
    
    println!("value for c: {:?}", c);
    dbg!(product_mod_p);
    assert!(c == Scalar::from_uint(U448::from(product_mod_p.0)));
}
