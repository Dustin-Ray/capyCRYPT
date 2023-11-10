use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConditionallyNegatable};
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

    /// Negates a field element
    pub(crate) fn negate(&self) -> FieldElement {
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
    pub fn invert(&self) -> FieldElement {
        // Addition chain taken from https://github.com/mmcloughlin/addchain
        let _1 = self;
        let _10 = _1.square();
        let _11 = *_1 * _10;
        let _110 = _11.square();
        let _111 = *_1 * _110;
        let _111000 = _111.square_n(3);
        let _111111 = _111 * _111000;

        let x12 = _111111.square_n(6) * _111111;
        let x24 = x12.square_n(12) * x12;
        let i34 = x24.square_n(6);
        let x30 = _111111 * i34;
        let x48 = i34.square_n(18) * x24;
        let x96 = x48.square_n(48) * x48;
        let x192 = x96.square_n(96) * x96;
        let x222 = x192.square_n(30) * x30;
        let x223 = x222.square() * *_1;

        (x223.square_n(223) * x222).square_n(2) * *_1
    }

    /// Squares a field element  `n` times
    fn square_n(&self, mut n: u32) -> FieldElement {
        let mut result = self.square();

        // Decrease value by 1 since we just did a squaring
        n = n - 1;

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