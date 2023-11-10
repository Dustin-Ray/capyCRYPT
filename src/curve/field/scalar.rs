use crypto_bigint::{impl_modulus, modular::constant_mod::ResidueParams, NonZero, U448};

pub const R_448: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";

impl_modulus!(
    Modulus,
    U448,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
);

pub struct Scalar {
    pub val: U448,
}

impl Scalar {
    /// Divides a scalar by four without reducing mod p
    /// This is used in the 2-isogeny when mapping points from Ed448-Goldilocks
    /// to Twisted-Goldilocks
    pub fn div_four(&mut self) {
        self.val = self
            .val
            .div_rem(&NonZero::new(U448::from(4_u64)).unwrap())
            .0;
    }
}

/// adapated from https://github.com/crate-crypto/Ed448-Goldilocks/blob/master/src/field/scalar.rs
fn montgomery_multiply_64(x: &U448, y: &U448, montgomery_factor: &U448) -> U448 {
    let mut result = U448::ZERO;
    let mut carry = 0;

    // Loop over the limbs of x and y, multiplying and adding to get the result.
    for i in 0..x.as_limbs().len() {
        let mut chain: u128 = 0; // Using u128 for the chain to handle potential overflow.

        // Perform the multiplication-addition for each limb.
        for (j, &ylimb) in y.as_limbs().iter().enumerate() {
            chain +=
                u128::from(x.as_limbs()[i]) * u128::from(ylimb) + u128::from(result.as_limbs()[j]);
            result.as_limbs_mut()[j] = crypto_bigint::Limb(chain as u64);
            chain >>= 64;
        }

        let saved = chain as u64;
        // Calculate the multiplicand for the Montgomery operation.
        let multiplicand = result.as_limbs()[0].wrapping_mul(montgomery_factor.as_limbs()[0]);

        chain = 0;
        for (j, &mlimb) in Modulus::MODULUS.as_limbs().iter().enumerate() {
            chain +=
                (u128::from(multiplicand)) * u128::from(mlimb) + u128::from(result.as_limbs()[j]);
            if j > 0 {
                result.as_limbs_mut()[j - 1] = crypto_bigint::Limb(chain as u64);
            }
            chain >>= 64;
        }

        // Add the carried value from previous iteration and the saved value.
        chain += (saved as u128) + (carry as u128);
        result.as_limbs_mut()[x.as_limbs().len() - 1] = crypto_bigint::Limb(chain as u64);
        carry = (chain >> 64) as u64;
    }

    // Assuming reduction is done elsewhere, return the result directly.
    result = result.sub_mod(&Modulus::MODULUS, &Modulus::MODULUS);
    result
}

// #[test]
// fn test_mul() {
//     // let a = U448::from_be_hex("1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3");
//     // let b = U448::from_be_hex("16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42");

//     // let c = U448::from_be_hex("6C17D05228B01E52DA3A3E7E30972D2A88A365302E7D8564935AACB2172149FD741AA3027F1329058E8AF8E98DFA3CA13978982627E005F6");

//     // const R: U448 = Uint::MAX
//     //     .const_rem(&Modulus::MODULUS)
//     //     .0
//     //     .wrapping_add(&Uint::ONE);

//     // // let res = montgomery_multiply(&a, &b, &R);

//     // let product_mod_p = montgomery_reduction(&a.mul_wide(&b), &Modulus::MODULUS, Modulus::MOD_NEG_INV);

//     // println!("{:?}", res);
//     // assert!(c == res && res == product_mod_p)
// }

#[test]
fn test_div_rem() {
    let a = U448::from(8_u64);
    let b = NonZero::new(U448::from(4_u64)).unwrap();
    let res = a.div_rem(&b);
    // 8 / 4 = 2 with no remainder
    assert!(res.0 == U448::from(2_u64));
    assert!(res.1 == U448::ZERO);
}
