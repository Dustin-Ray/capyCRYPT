#![allow(non_snake_case)]
use std::ops::Mul;

use super::{
    extensible_edwards::ExtensibleCurvePoint,
    field::{field_element::FieldElement, lookup_table::LookupTable, scalar::Scalar},
};
use crypto_bigint::{
    subtle::{Choice, ConditionallySelectable, ConditionallyNegatable},
    Limb,
};
use fiat_crypto::p448_solinas_64::*;

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

/// All curves defined here:
/// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
#[derive(Debug, Clone, Copy)]
pub enum EdCurves {
    E448,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtendedCurvePoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

pub struct AffineEdwards {
    pub X: FieldElement,
    pub Y: FieldElement,
}

impl ExtendedCurvePoint {
    pub fn id_point() -> ExtendedCurvePoint {
        ExtendedCurvePoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }

    //https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
    // These formulas are unified, so for now we can use it for doubling. Will refactor later for speed
    pub fn add(&self, other: &ExtendedCurvePoint) -> ExtendedCurvePoint {
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

        ExtendedCurvePoint { X, Y, Z, T }
    }

    /// Edwards_Isogeny is derived from the doubling formula
    /// XXX: There is a duplicate method in the twisted edwards module to compute the dual isogeny
    /// XXX: Not much point trying to make it generic I think. So what we can do is optimise each respective isogeny method for a=1 or a = -1 (currently, I just made it really slow and simple)
    fn edwards_isogeny(&self, a: FieldElement) -> ExtendedCurvePoint {
        // Convert to affine now, then derive extended version later
        let affine = self.to_affine();
        let x = affine.X;
        let y = affine.Y;

        // Compute x
        let xy = x * y;
        let x_numerator = xy + xy;
        let x_denom = y.square() - (a * x.square());
        let new_x = x_numerator * x_denom.invert();

        // Compute y
        let y_numerator = y.square() + (a * x.square());
        let y_denom = (FieldElement::one() + FieldElement::one()) - y.square() - (a * x.square());
        let new_y = y_numerator * y_denom.invert();

        ExtendedCurvePoint {
            X: new_x,
            Y: new_y,
            Z: FieldElement::one(),
            T: new_x * new_y,
        }
    }

    pub fn to_twisted(&self) -> ExtendedCurvePoint {
        self.edwards_isogeny(FieldElement::one())
    }

    /// Uses a 2-isogeny to map the point to the Ed448-Goldilocks
    pub fn to_untwisted(&self) -> ExtendedCurvePoint {
        self.edwards_isogeny(FieldElement::minus_one())
    }

    pub fn to_affine(&self) -> AffineEdwards {
        let INV_Z = self.Z.invert();

        let mut X = self.X * INV_Z;
        X.strong_reduce();

        let mut Y = self.Y * INV_Z;
        Y.strong_reduce();

        AffineEdwards { X, Y }
    }

    pub fn double(&self) -> ExtendedCurvePoint {
        self.add(&self)
    }

    pub fn variable_base(point: &ExtendedCurvePoint, s: &Scalar) -> ExtendedCurvePoint {
        let mut result = ExtensibleCurvePoint::identity();

        // Recode Scalar
        let scalar = s.to_radix_16();

        let lookup = LookupTable::from(point);

        for i in (0..113).rev() {
            result = result.double();
            result = result.double();
            result = result.double();
            result = result.double();

            // The mask is the top bit, will be 1 for negative numbers, 0 for positive numbers
            let mask = scalar[i] >> 7;
            let sign = mask & 0x1;
            // Use the mask to get the absolute value of scalar
            let abs_value = ((scalar[i] + mask) ^ mask) as u32;

            let mut neg_P = lookup.select(abs_value);
            neg_P.conditional_negate(Choice::from((sign) as u8));

            result = result.add_projective_niels(&neg_P);
        }

        result.to_extended()
    }

    /// Converts an ExtendedPoint to an ExtensiblePoint
    pub fn to_extensible(&self) -> ExtensibleCurvePoint {
        ExtensibleCurvePoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T1: self.T,
            T2: FieldElement::one(),
        }
    }

    // Variant of Niels, where a Z coordinate is added for unmixed readdition
    // ((y+x)/2, (y-x)/2, dxy, Z)
    pub fn to_projective_niels(&self) -> ExtendedCurvePoint {
        ExtendedCurvePoint {
            X: self.Y + self.X,
            Y: self.Y - self.X,
            Z: self.Z,
            T: EDWARDS_D * self.X * self.Y,
        }
    }

    // Generates the curve
    pub fn generator() -> ExtendedCurvePoint {
        ExtendedCurvePoint {
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
    pub fn scalar_mod_four(&self, scalar: &Scalar) -> ExtendedCurvePoint {
        // Compute compute (scalar mod 4)
        let mut val_copy = scalar.val.clone();
        let s_mod_four = val_copy.as_limbs_mut()[0] & crypto_bigint::Limb(3);

        // Compute all possible values of (scalar mod 4) * P
        let zero_p = ExtendedCurvePoint::id_point();
        let one_p = self.clone();
        let two_p = one_p.double();
        let three_p = two_p.add(self);

        // Under the reasonable assumption that `==` is constant time
        // Then the whole function is constant time.
        // This should be cheaper than calling double_and_add or a scalar mul operation
        // as the number of possibilities are so small.
        // XXX: This claim has not been tested (although it sounds intuitive to me)
        let mut result = ExtendedCurvePoint::id_point();
        result.conditional_assign(&zero_p, Choice::from((s_mod_four == Limb(0)) as u8));
        result.conditional_assign(&one_p, Choice::from((s_mod_four == Limb(1)) as u8));
        result.conditional_assign(&two_p, Choice::from((s_mod_four == Limb(2)) as u8));
        result.conditional_assign(&three_p, Choice::from((s_mod_four == Limb(3)) as u8));

        result
    }

    /// Generic scalar multiplication to compute s*P
    pub fn scalar_mul(&self, scalar: &Scalar) -> ExtendedCurvePoint {
        // Compute floor(s/4)
        let mut scalar_div_four = scalar.clone();
        scalar_div_four.div_four();

        // Use isogeny and dual isogeny to compute phi^-1((s/4) * phi(P))
        let partial_result = Self::variable_base(&self.to_twisted(), &scalar_div_four).to_untwisted();
        // Add partial result to (scalar mod 4) * P
        partial_result.add(&self.scalar_mod_four(scalar))
    }
}

impl ConditionallySelectable for ExtendedCurvePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedCurvePoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

impl Mul<&Scalar> for &ExtendedCurvePoint {
    type Output = ExtendedCurvePoint;
    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: &Scalar) -> ExtendedCurvePoint {
        self.scalar_mul(&scalar)
    }
}
