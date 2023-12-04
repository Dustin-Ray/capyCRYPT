use std::ops::{Mul, Div};

use crypto_bigint::{
    impl_modulus,
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
        self.val = self
            .val
            .div(&NonZero::new(U448::from(4_u64)).unwrap());
    }

    pub fn invert(&mut self) {
        self.val.inv_mod(&U448::from_be_hex(R_448));
    }

    pub fn from(val: u64) -> Self {
        Scalar {
            val: U448::from(val),
        }
    }

    pub fn from_uint(val: U448) -> Self {
        Scalar { val }
    }

    pub fn to_radix_16(&self) -> [i8; 113] {
        let bytes = self.val.to_be_bytes();
        let mut output = [0i8; 113];

        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        for i in 0..56 {
            output[2 * i] = (bytes[i] & 15) as i8; // Lower nibble
            output[2 * i + 1] = ((bytes[i] >> 4) & 15) as i8; // Upper nibble
        }

        // Re-center coefficients to be between [-8, 8)
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
    let a: Scalar = Scalar::from_uint(U448::from_be_hex("1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3"));
    let b: Scalar = Scalar::from_uint(U448::from_be_hex("16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42"));
    let c: Scalar = Scalar::from_uint(U448::from_be_hex("6C17D05228B01E52DA3A3E7E30972D2A88A365302E7D8564935AACB2172149FD741AA3027F1329058E8AF8E98DFA3CA13978982627E005F6"));

    let res: Scalar = a * b;

    let product_mod_p = Scalar::from_uint(crypto_bigint::modular::montgomery_reduction(
        &a.val.mul_wide(&b.val),
        &Modulus::MODULUS,
        Modulus::MOD_NEG_INV,
    ));

    println!("{:?}", res);
    assert!(c == res && res == product_mod_p);
    dbg!(res);
}
