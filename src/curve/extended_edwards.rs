#![allow(non_snake_case)]
use std::ops::Mul;

use super::{
    extensible_edwards::ExtensibleCurvePoint,
    field::{field_element::FieldElement, lookup_table::LookupTable, scalar::Scalar},
};
use crypto_bigint::{
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq},
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
    /// ------------------------------
    /// ISOGENY OPERATIONS
    /// ------------------------------

    /// Edwards_Isogeny is derived from the doubling formula
    fn edwards_isogeny(&self, a: FieldElement) -> ExtendedCurvePoint {
        // Convert to affine now, then derive extended version later
        let affine = self.to_affine();
        let x = affine.X;
        let y = affine.Y;

        // Common computations
        let x_squared = x.square();
        let y_squared = y.square();
        let a_x_squared = a * x_squared;

        // Compute common denominator
        let common_denom = (FieldElement::one() + FieldElement::one()) - y_squared - a_x_squared;
        let inverted_common_denom = common_denom.invert();

        // Compute x
        let xy = x * y;
        let x_numerator = xy + xy;
        let new_x = x_numerator * inverted_common_denom;

        // Compute y
        let y_numerator = y_squared + a_x_squared;
        let new_y = y_numerator * inverted_common_denom;

        ExtendedCurvePoint {
            X: new_x,
            Y: new_y,
            Z: FieldElement::one(),
            T: new_x * new_y,
        }
    }

    // Variable-base scalar multiplication with lookup table
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

    /// ------------------------------
    /// CURVE POINT COERCION
    /// ------------------------------

    /// Lifts extended to twisted extended
    pub fn to_twisted(&self) -> ExtendedCurvePoint {
        self.edwards_isogeny(FieldElement::one())
    }

    /// Uses a 2-isogeny to map the point to the Ed448-Goldilocks
    pub fn to_untwisted(&self) -> ExtendedCurvePoint {
        self.edwards_isogeny(FieldElement::minus_one())
    }

    /// Brings an extended Edwards down to affine x, y
    pub fn to_affine(&self) -> AffineEdwards {
        let INV_Z = self.Z.invert();

        let mut X = self.X * INV_Z;
        X.strong_reduce();

        let mut Y = self.Y * INV_Z;
        Y.strong_reduce();

        AffineEdwards { X, Y }
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

    /// ------------------------------
    /// CURVE POINT ARITHMETIC
    /// ------------------------------

    // https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
    pub fn add(&self, other: &ExtendedCurvePoint) -> ExtendedCurvePoint {
        let aXX = self.X * other.X;
        let dTT = EDWARDS_D * self.T * other.T;
        let ZZ = self.Z * other.Z;
        let YY = self.Y * other.Y;
        let X1Y2_plus_Y1X2 = (self.X * other.Y) + (self.Y * other.X);

        let X = X1Y2_plus_Y1X2 * (ZZ - dTT);
        let Y = (YY - aXX) * (ZZ + dTT);
        let T = (YY - aXX) * X1Y2_plus_Y1X2;
        let Z = (ZZ - dTT) * (ZZ + dTT);

        ExtendedCurvePoint { X, Y, Z, T }
    }

    pub fn double(&self) -> ExtendedCurvePoint {
        self.add(self)
    }

    /// Returns (scalar mod 4) * P in constant time
    pub fn scalar_mod_four(&self, scalar: &Scalar) -> ExtendedCurvePoint {
        // Compute compute (scalar mod 4)
        let mut val_copy = scalar.val;
        let s_mod_four = val_copy.as_limbs_mut()[0] & crypto_bigint::Limb(3);

        // Compute all possible values of (scalar mod 4) * P
        let zero_p = ExtendedCurvePoint::id_point();
        let one_p = *self;
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
        let mut scalar_div_four = *scalar;
        scalar_div_four.div_four();

        // Use isogeny and dual isogeny to compute phi^-1((s/4) * phi(P))
        let partial_result =
            Self::variable_base(&self.to_twisted(), &scalar_div_four).to_untwisted();
        // Add partial result to (scalar mod 4) * P
        partial_result.add(&self.scalar_mod_four(scalar))
    }

    /// ------------------------------
    /// GROUP OPERATIONS
    /// ------------------------------

    /// Generates the curve
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

    /// Neutral curve point
    pub fn id_point() -> ExtendedCurvePoint {
        ExtendedCurvePoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }
}

/// Select a point in fixed time
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
        self.scalar_mul(scalar)
    }
}

impl Mul<Scalar> for ExtendedCurvePoint {
    type Output = ExtendedCurvePoint;
    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: Scalar) -> ExtendedCurvePoint {
        self.scalar_mul(&scalar)
    }
}

impl ConstantTimeEq for ExtendedCurvePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let XZ = self.X * other.Z;
        let ZX = self.Z * other.X;

        let YZ = self.Y * other.Z;
        let ZY = self.Z * other.Y;

        (XZ.ct_eq(&ZX)) & (YZ.ct_eq(&ZY))
    }
}

impl PartialEq for ExtendedCurvePoint {
    fn eq(&self, other: &ExtendedCurvePoint) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for ExtendedCurvePoint {}

#[test]
pub fn test_g_times_zero_id() {
    let p = ExtendedCurvePoint::generator();
    let zero = Scalar::from(0_u64);
    let res = p * zero;
    let id = ExtendedCurvePoint::id_point();

    assert!(res == id)
}

#[test]
pub fn test_g_times_one_g() {
    let p = ExtendedCurvePoint::generator();
    let one = Scalar::from(1_u64);
    let res = p * one;
    let id = ExtendedCurvePoint::generator();

    assert!(res == id)
}

#[test]
pub fn test_g_times_two_g_plus_g() {
    let p = ExtendedCurvePoint::generator();
    let two = Scalar::from(2_u64);
    let res = p * two;
    let res2 = p.add(&p);
    assert!(res == res2)
}
