use fiat_crypto::p448_solinas_64::*;
use std::ops::Add;

#[derive(Copy, Clone)]
pub struct FieldElement(pub(crate) fiat_p448_tight_field_element);

impl std::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FieldElement56").field(&self.0 .0).finish()
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
}
