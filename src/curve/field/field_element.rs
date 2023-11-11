use crypto_bigint::subtle::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq,
};
use fiat_crypto::p448_solinas_64::*;
use std::ops::{Add, Mul, Sub};

#[derive(Copy, Clone)]
pub struct FieldElement(pub(crate) fiat_p448_tight_field_element);

impl std::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FieldElement").field(&self.0 .0).finish()
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: FieldElement) -> Self::Output {
        let mut result_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_add(&mut result_loose, &self.0, &rhs.0);
        let mut result = FieldElement::zero();
        fiat_p448_carry(&mut result.0, &result_loose);
        result
    }
}

impl FieldElement {
    pub const fn zero() -> FieldElement {
        FieldElement(fiat_p448_tight_field_element([0; 8]))
    }
    pub const fn one() -> FieldElement {
        FieldElement(fiat_p448_tight_field_element([1, 0, 0, 0, 0, 0, 0, 0]))
    }
    pub fn minus_one() -> FieldElement {
        FieldElement(fiat_p448_tight_field_element([
            144115188075855869,
            144115188075855870,
            144115188075855870,
            144115188075855870,
            144115188075855868,
            144115188075855870,
            144115188075855870,
            144115188075855870,
        ]))
    }

    // We encode the Field element by storing each consecutive into a u64
    pub fn to_bytes(&self) -> [u8; 56] {
        let mut res = [0u8; 56];
        fiat_p448_to_bytes(&mut res, &self.0);
        res
    }

    /// Helper function for internally constructing a field element
    pub const fn from_raw_slice(slice: [u64; 8]) -> FieldElement {
        FieldElement(fiat_p448_tight_field_element(slice))
    }

    /// This does not check if the encoding is canonical (ie if the input is reduced)
    /// We parse in chunks of 56 bytes, the first 28 bytes will contain the i'th limb
    /// and the second 28 bytes will contain the (2i+1)'th limb
    pub fn from_bytes(bytes: &[u8; 56]) -> FieldElement {
        let mut res = FieldElement::zero();
        fiat_p448_from_bytes(&mut res.0, bytes);
        res
    }

    /// Negates a field element
    pub fn negate(&self) -> FieldElement {
        let mut result_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_opp(&mut result_loose, &self.0);
        let mut result = FieldElement::zero();
        fiat_p448_carry(&mut result.0, &result_loose);
        result
    }

    /// Squares a field element
    pub fn square(&self) -> FieldElement {
        let mut self_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_relax(&mut self_loose, &self.0);
        let mut result = FieldElement::zero();
        fiat_p448_carry_square(&mut result.0, &self_loose);
        result
    }

    /// Inverts a field element
    /// Previous chain length: 462, new length 460
    /// Addition chain taken from https://github.com/mmcloughlin/addchain

    pub fn invert(&self) -> FieldElement {
        let base = self;
        let base_square = base.square();
        let base_cubed = *base * base_square;
        let base_pow_six = base_cubed.square();
        let base_pow_seven = *base * base_pow_six;
        let base_56 = base_pow_seven.square_n(3); // Represents base^56
        let base_63 = base_pow_seven * base_56; // Represents base^63

        // Additional steps with more descriptive variable names
        let step1 = base_63.square_n(6) * base_63;
        let step2 = step1.square_n(12) * step1;
        let step3 = step2.square_n(6);
        let step4 = base_63 * step3;
        let step5 = step3.square_n(18) * step2;
        let step6 = step5.square_n(48) * step5;
        let step7 = step6.square_n(96) * step6;
        let step8 = step7.square_n(30) * step4;
        let step9 = step8.square() * *base;

        (step9.square_n(223) * step8).square_n(2) * *base
    }

    /// Squares a field element  `n` times
    fn square_n(&self, mut n: u32) -> FieldElement {
        let mut result = self.square();

        // Decrease value by 1 since we just did a squaring
        n -= 1;

        for _ in 0..n {
            result = result.square();
        }

        result
    }

    /// Reduces the field element to a canonical representation
    /// This is used when checking equality between two field elements and
    /// when encoding a field element
    pub(crate) fn strong_reduce(&mut self) {
        let mut self_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_relax(&mut self_loose, &self.0);
        fiat_p448_carry(&mut self.0, &self_loose);
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;
    fn mul(self, rhs: &FieldElement) -> Self::Output {
        let mut result = FieldElement::zero();
        let mut self_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_relax(&mut self_loose, &self.0);
        let mut rhs_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_relax(&mut rhs_loose, &rhs.0);
        fiat_p448_carry_mul(&mut result.0, &self_loose, &rhs_loose);
        result
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;
    fn mul(self, rhs: FieldElement) -> Self::Output {
        &self * &rhs
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;
    fn sub(self, rhs: FieldElement) -> Self::Output {
        let mut result_loose = fiat_p448_loose_field_element([0; 8]);
        fiat_p448_sub(&mut result_loose, &self.0, &rhs.0);
        let mut result = FieldElement::zero();
        fiat_p448_carry(&mut result.0, &result_loose);
        result
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        let mut result = FieldElement::zero();
        fiat_p448_selectznz(&mut (result.0).0, choice.unwrap_u8(), &(a.0).0, &(b.0).0);
        result
    }
}

impl ConditionallyNegatable for FieldElement {
    fn conditional_negate(&mut self, choice: Choice) {
        let self_neg = self.clone().negate();
        self.conditional_assign(&self_neg, choice);
    }
}
