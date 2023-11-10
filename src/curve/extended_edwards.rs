#![allow(non_snake_case)]
use std::ops::Mul;

use super::field::{field_element::FieldElement, scalar::Scalar};
use crypto_bigint::{
    subtle::{Choice, ConditionallySelectable},
    Limb,
};
use fiat_crypto::p448_solinas_64::*;

/// All curves defined here:
/// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
#[derive(Debug, Clone, Copy)]
pub enum EdCurves {
    E448,
}

#[derive(Debug, Clone, Copy)]
pub struct EdCurvePoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

/// Edwards `d`, equals to -39081
pub const EDWARDS_D: FieldElement = FieldElement(fiat_p448_tight_field_element([
    144115188075816789,
    144115188075855870,
    144115188075855870,
    144115188075855870,
    144115188075855868,
    144115188075855870,
    144115188075855870,
    144115188075855870,
]));

impl EdCurvePoint {
    pub fn id_point() -> EdCurvePoint {
        EdCurvePoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }

    //https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
    // These formulas are unified, so for now we can use it for doubling. Will refactor later for speed
    pub fn add(&self, other: &EdCurvePoint) -> EdCurvePoint {
        let aXX = self.X * other.X; // aX1X2
        let dTT = EDWARDS_D * self.T * other.T; // dT1T2
        let ZZ = self.Z * other.Z; // Z1Z2
        let YY = self.Y * other.Y;

        let X = {
            let x_1 = (self.X * other.Y) + (self.Y * other.X);
            let x_2 = ZZ - dTT;
            x_1 * x_2
        };
        let Y = {
            let y_1 = YY - aXX;
            let y_2 = ZZ + dTT;
            y_1 * y_2
        };

        let T = {
            let t_1 = YY - aXX;
            let t_2 = (self.X * other.Y) + (self.Y * other.X);
            t_1 * t_2
        };

        let Z = { (ZZ - dTT) * (ZZ + dTT) };

        EdCurvePoint { X, Y, Z, T }
    }

    pub fn double(&self) -> EdCurvePoint {
        self.add(&self)
    }

    // Variant of Niels, where a Z coordinate is added for unmixed readdition
    // ((y+x)/2, (y-x)/2, dxy, Z)
    pub fn to_projective_niels(&self) -> EdCurvePoint {
        EdCurvePoint {
            X: self.Y + self.X,
            Y: self.Y - self.X,
            Z: self.Z,
            T: EDWARDS_D * self.X * self.Y,
        }
    }

    // Generates the curve
    pub fn generator() -> EdCurvePoint {
        EdCurvePoint {
            X: FieldElement(fiat_p448_tight_field_element([
                10880955091566686,
                36276784145337894,
                69571282115576635,
                46113124210880026,
                4247859732800292,
                15440021224255559,
                66747077793030847,
                22264495316135181,
            ])),
            Y: FieldElement(fiat_p448_tight_field_element([
                2385235625966100,
                5396741696826776,
                8134720567442877,
                1584133578609663,
                46047824121994270,
                56121598560924524,
                10283140089599689,
                29624444337960636,
            ])),
            Z: FieldElement(fiat_p448_tight_field_element([1, 0, 0, 0, 0, 0, 0, 0])),
            T: FieldElement(fiat_p448_tight_field_element([
                1796939199780339,
                45174008172060139,
                40732174862907279,
                63672088496536030,
                37244660935497319,
                41035719659624511,
                30626637035688077,
                56117654178374172,
            ])),
        }
    }

    /// Returns (scalar mod 4) * P in constant time
    pub fn scalar_mod_four(&self, scalar: &mut Scalar) -> EdCurvePoint {
        // Compute compute (scalar mod 4)
        let s_mod_four = scalar.val.as_limbs_mut()[0] & crypto_bigint::Limb(3);

        // Compute all possible values of (scalar mod 4) * P
        let zero_p = EdCurvePoint::id_point();
        let one_p = self.clone();
        let two_p = one_p.double();
        let three_p = two_p.add(self);

        // Under the reasonable assumption that `==` is constant time
        // Then the whole function is constant time.
        // This should be cheaper than calling double_and_add or a scalar mul operation
        // as the number of possibilities are so small.
        // XXX: This claim has not been tested (although it sounds intuitive to me)
        let mut result = EdCurvePoint::id_point();
        result.conditional_assign(&zero_p, Choice::from((s_mod_four == Limb(0)) as u8));
        result.conditional_assign(&one_p, Choice::from((s_mod_four == Limb(1)) as u8));
        result.conditional_assign(&two_p, Choice::from((s_mod_four == Limb(2)) as u8));
        result.conditional_assign(&three_p, Choice::from((s_mod_four == Limb(3)) as u8));

        result
    }

    pub fn scalar_mul(&self, rhs: &Scalar) -> EdCurvePoint {
        *self
    }
}

impl ConditionallySelectable for EdCurvePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        EdCurvePoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

impl Mul<&Scalar> for &EdCurvePoint {
    type Output = EdCurvePoint;
    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: &Scalar) -> EdCurvePoint {
        self.scalar_mul(scalar)
    }
}
