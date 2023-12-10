#![allow(non_snake_case)]
use super::{
    affine::AffinePoint,
    field::{field_element::FieldElement, lookup_table::LookupTable, scalar::Scalar},
    twisted_edwards::TwistedPoint,
};
use crypto_bigint::subtle::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq,
};
use fiat_crypto::p448_solinas_64::*;
use std::ops::{Add, Mul, Neg};

/// Extended coordinates extend projective coordinates by adding an
/// additional auxiliary coordinate to speed up certain calculations.
/// A point in extended coordinates is represented as (X:Y:Z:T), with the
/// additional constraint that T = XY/Z.
///
/// This representation allows certain operations, like point doubling and
/// addition, to be performed more efficiently.The Edwards curve equation in
/// extended coordinates doesn't change form but utilizes the T coordinate
/// to simplify the calculation of some operations.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedPoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

impl ExtendedPoint {
    /// https://www.shiftleft.org/papers/isogeny/isogeny.pdf
    /// page 4 specifies s is always known to be a multiple of 4
    ///
    /// Performs variable-base scalar multiplication on an elliptic curve point.
    ///
    /// This function multiplies an elliptic curve point (`point`) with a scalar (`s`) and returns
    /// the resulting point. It is optimized for variable-base multiplication, which is a common
    /// operation in elliptic curve cryptography, particularly in contexts like key exchange or
    /// digital signature generation.
    ///
    /// # Algorithm
    ///
    /// The function employs the following steps in the multiplication process:
    ///
    /// 1. Convert the scalar `s` to radix-16 representation using `to_radix_16`.
    /// 2. Create a lookup table from the input point for fast scalar multiplication.
    /// 3. Iterate over each digit of the radix-16 scalar, in reverse order.
    ///    - In each iteration, perform four point doublings on the accumulating result.
    ///    - Extract the sign and absolute value of the current scalar digit.
    ///    - Select the corresponding point from the lookup table, conditionally negate it
    ///      based on the sign, and add it to the result.
    /// 4. Convert the result from the extensible point representation back to the extended point.
    ///
    /// This approach combines the efficiency of radix-16 scalar representation with a pre-computed
    /// lookup table to accelerate the point multiplication process.
    ///
    /// # Arguments
    ///
    /// * `point`: A reference to an `ExtendedPoint`, the elliptic curve point to be multiplied.
    /// * `s`: A reference to a `Scalar`, the scalar by which the point is to be multiplied.
    ///
    /// # Returns
    ///
    /// An `ExtendedPoint` that is the result of the scalar multiplication of `point` by `s`.
    pub fn variable_base(point: &ExtendedPoint, s: &Scalar) -> ExtendedPoint {
        // We make use of the faster doubling for ExtensiblePoints
        let mut result = TwistedPoint::identity();

        let scalar = s.to_radix_16();
        let lookup = LookupTable::from(point);

        for i in (0..113).rev() {
            result = result.double();
            result = result.double();
            result = result.double();
            result = result.double();

            let mask = scalar[i] >> 7;
            let sign = mask & 0x1;
            let abs_value = ((scalar[i] + mask) ^ mask) as u32;

            let mut neg_P = lookup.select(abs_value);
            neg_P.conditional_negate(Choice::from((sign) as u8));

            result = result.add_projective_niels(&neg_P);
        }

        // Convert back to extended when complete
        result.to_extended()
    }

    // ------------------------------
    // CURVE POINT PROJECTION
    // ------------------------------

    /// Projects to ExtendedPoint to ExtensiblePoint to
    /// leverage faster addition and doubling
    pub fn to_extensible(&self) -> TwistedPoint {
        TwistedPoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T1: self.T,
            T2: FieldElement::one(),
        }
    }

    pub fn to_affine(&self) -> AffinePoint {
        let INV_Z = self.Z.invert();

        let mut x = self.X * INV_Z;
        x.strong_reduce();

        let mut y = self.Y * INV_Z;
        y.strong_reduce();

        AffinePoint { x, y }
    }

    // ------------------------------
    // CURVE POINT ARITHMETIC
    // ------------------------------

    pub fn add(&self, other: &ExtendedPoint) -> ExtendedPoint {
        self.to_extensible().add_extended(other).to_extended()
    }

    pub fn double(&self) -> ExtendedPoint {
        self.to_extensible().double().to_extended()
    }

    pub fn negate(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: self.X.negate(),
            Y: self.Y,
            Z: self.Z,
            T: self.T.negate(),
        }
    }

    // ------------------------------
    // GROUP OPERATIONS
    // ------------------------------

    /// Generates the 2-isogenous twisted curve
    pub fn tw_generator() -> ExtendedPoint {
        ExtendedPoint {
            X: FieldElement(fiat_p448_tight_field_element([
                0,
                72057594037927936,
                72057594037927935,
                36028797018963967,
                72057594037927934,
                72057594037927935,
                72057594037927935,
                36028797018963967,
            ])),
            Y: FieldElement(fiat_p448_tight_field_element([
                27155415521118820,
                3410937204744648,
                19376965222209947,
                22594032279754776,
                21520481577673772,
                10141917371396176,
                59827755213158602,
                37445921829569158,
            ])),
            Z: FieldElement(fiat_p448_tight_field_element([1, 0, 0, 0, 0, 0, 0, 0])),
            T: FieldElement(fiat_p448_tight_field_element([
                64114820220813573,
                27592348249940115,
                21918321435874307,
                45908688348236165,
                34141937727972228,
                63575698147485199,
                22766751209138687,
                30740600843388580,
            ])),
        }
    }

    /// Neutral curve point
    pub fn id_point() -> ExtendedPoint {
        ExtendedPoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }
}

// ------------------------------
// TRAITS
// ------------------------------

/// Select a point in fixed time
impl ConditionallySelectable for ExtendedPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

impl Mul<Scalar> for ExtendedPoint {
    type Output = ExtendedPoint;
    fn mul(self, scalar: Scalar) -> ExtendedPoint {
        ExtendedPoint::variable_base(&self, &scalar)
    }
}

impl Add<ExtendedPoint> for &ExtendedPoint {
    type Output = ExtendedPoint;
    fn add(self, rhs: ExtendedPoint) -> ExtendedPoint {
        ExtendedPoint::add(self, &rhs)
    }
}

impl Add<ExtendedPoint> for ExtendedPoint {
    type Output = ExtendedPoint;
    fn add(self, rhs: ExtendedPoint) -> ExtendedPoint {
        ExtendedPoint::add(&self, &rhs)
    }
}

impl Neg for ExtendedPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl ConstantTimeEq for ExtendedPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let XZ = self.X * other.Z;
        let ZX = self.Z * other.X;

        let YZ = self.Y * other.Z;
        let ZY = self.Z * other.Y;

        (XZ.ct_eq(&ZX)) & (YZ.ct_eq(&ZY))
    }
}

impl PartialEq for ExtendedPoint {
    fn eq(&self, other: &ExtendedPoint) -> bool {
        self.ct_eq(other).into()
    }
}
