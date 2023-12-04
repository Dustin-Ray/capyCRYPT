#![allow(non_snake_case)]
use super::{
    extended_edwards::ExtendedCurvePoint, field::field_element::FieldElement,
    projective_niels::ProjectiveNielsPoint,
};
use fiat_crypto::p448_solinas_64::fiat_p448_tight_field_element;

/// ------------------------------
/// CONSTANTS
/// ------------------------------

/// Twice the Twisted Edwards d which equals to -78164
pub const TWO_TIMES_TWISTED_D: FieldElement = FieldElement(fiat_p448_tight_field_element([
    144115188075777706,
    144115188075855870,
    144115188075855870,
    144115188075855870,
    144115188075855868,
    144115188075855870,
    144115188075855870,
    144115188075855870,
]));

/// Twisted Edwards D equals `d-1`, equals to -39082
pub const TWISTED_D: FieldElement = FieldElement(fiat_p448_tight_field_element([
    144115188075816788,
    144115188075855870,
    144115188075855870,
    144115188075855870,
    144115188075855868,
    144115188075855870,
    144115188075855870,
    144115188075855870,
]));

/// This is the representation that we will do most of the group operations on.
/// In affine (x,y) is the extensible point (X, Y, Z, T1, T2)
/// Where x = X/Z , y = Y/Z , T1 * T2 = T
pub struct ExtensibleCurvePoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T1: FieldElement,
    pub T2: FieldElement,
}

impl ExtensibleCurvePoint {
    /// ------------------------------
    /// GROUP OPERATIONS
    /// ------------------------------

    pub fn identity() -> ExtensibleCurvePoint {
        ExtensibleCurvePoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T1: FieldElement::zero(),
            T2: FieldElement::one(),
        }
    }

    /// ------------------------------
    /// CURVE POINT COERCION
    /// ------------------------------

    /// Converts an Extensible point to a ProjectiveNiels Point
    pub fn to_projective_niels(&self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint {
            Y_plus_X: self.X + self.Y,
            Y_minus_X: self.Y - self.X,
            Z: self.Z + self.Z,
            Td: self.T1 * self.T2 * TWO_TIMES_TWISTED_D,
        }
    }

    /// Converts an extensible point to an extended point
    pub fn to_extended(&self) -> ExtendedCurvePoint {
        ExtendedCurvePoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T: self.T1 * self.T2,
        }
    }

    /// Adds two extensible points together by converting the other point to a ExtendedPoint
    pub fn add_extensible(&self, other: &ExtensibleCurvePoint) -> ExtensibleCurvePoint {
        self.add_extended(&other.to_extended())
    }

    /// ------------------------------
    /// CURVE POINT ARITHMETIC
    /// ------------------------------

    /// Adds an extensible point to a ProjectiveNiels point
    /// Returns an extensible point
    /// (3.1)[Last set of formulas] https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    /// This differs from the formula above by a factor of 2. Saving 1 Double
    /// Cost 8M
    pub fn add_projective_niels(&self, other: &ProjectiveNielsPoint) -> ExtensibleCurvePoint {
        // This is the only step which makes it different than adding an AffineNielsPoint
        let Z = self.Z * other.Z;

        let A = (self.Y - self.X) * other.Y_minus_X;
        let B = (self.Y + self.X) * other.Y_plus_X;
        let C = other.Td * self.T1 * self.T2;
        let D = B + A;
        let E = B - A;
        let F = Z - C;
        let G = Z + C;
        ExtensibleCurvePoint {
            X: E * F,
            Y: G * D,
            Z: F * G,
            T1: E,
            T2: D,
        }
    }

    /// Adds an extensible point to an extended point
    /// Returns an extensible point
    /// (3.1) https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    pub fn add_extended(&self, other: &ExtendedCurvePoint) -> ExtensibleCurvePoint {
        let A = self.X * other.X;
        let B = self.Y * other.Y;
        let C = self.T1 * self.T2 * other.T * TWISTED_D;
        let D = self.Z * other.Z;
        let E = (self.X + self.Y) * (other.X + other.Y) - A - B;
        let F = D - C;
        let G = D + C;
        let H = B + A;
        ExtensibleCurvePoint {
            X: E * F,
            Y: G * H,
            T1: E,
            T2: H,
            Z: F * G,
        }
    }

    /// Doubles a point
    /// (3.3) https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    pub fn double(&self) -> ExtensibleCurvePoint {
        let A = self.X.square();
        let B = self.Y.square();
        let C = self.Z.square() + self.Z.square();
        let D = A.negate();
        let E = (self.X + self.Y).square() - A - B;
        let G = D + B;
        let F = G - C;
        let H = D - B;
        ExtensibleCurvePoint {
            X: E * F,
            Y: G * H,
            Z: F * G,
            T1: E,
            T2: H,
        }
    }

    /// Subtracts an extensible point from an extended point
    /// Returns an extensible point
    /// This is a direct modification of the addition formula to the negation of `other`
    pub fn sub_extended(&self, other: &ExtendedCurvePoint) -> ExtensibleCurvePoint {
        let A = self.X * other.X;
        let B = self.Y * other.Y;
        let C = self.T1 * self.T2 * other.T * TWISTED_D;
        let D = self.Z * other.Z;
        let E = (self.X + self.Y) * (other.Y - other.X) + A - B;
        let F = D + C;
        let G = D - C;
        let H = B - A;
        ExtensibleCurvePoint {
            X: E * F,
            Y: G * H,
            T1: E,
            T2: H,
            Z: F * G,
        }
    }
}
