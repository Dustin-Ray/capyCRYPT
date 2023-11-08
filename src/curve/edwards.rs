use num::Num;
use num_bigint::BigInt as Integer;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Neg;

/// All curves defined here:
/// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
#[derive(Debug, Clone, Copy)]
pub enum EdCurves {
    E448,
}

/// d, n, p, and r values for each curve
mod ed_curve_constants {

    pub const D_448: i32 = -39081;
    pub const N_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDF3288FA7113B6D26BB58DA4085B309CA37163D548DE30A4AAD6113CC";
    pub const P_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    pub const R_448: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";
    pub const G_Y: &str = "C66F6F0565E6D0B5F2BB263CEBB9F8540EB046F40ED0FFF7F84D84653B428D989AABFF93B6BF700801228094E3DD0C2D1C600E3B0BCCFC32";
}
#[derive(Debug)]
/// # CurvePoint - Edwards Form
/// An Edwards curve takes the form: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦², where:
/// * x: x-coordinate
/// * y: y-coordinate
/// * p: prime defining finite field 𝔽𝑝
/// * d: d coefficient for Edwards curve equation, defines order
/// * r: order of curve, determined from d
/// * n: number of points on curve, equal to 4r
/// * curve: enumeration representing the requested curve
/// ## Supported Edward Curves:
/// This library supports multiple curves of Edwards form which can be used interchangebly
/// with supported model functionality. Current supported curves are:
/// * E222
/// * E382
/// * E448
/// * E521
/// ## Security claims
/// An analysis of security and performance provided by each curve is made in <https://eprint.iacr.org/2013/647.pdf>
pub struct EdCurvePoint {
    pub x: Integer,
    pub y: Integer,
    pub z: Integer,
    pub p: Integer,
    pub d: Integer,
    pub r: Integer,
    pub n: Integer,
    pub curve: EdCurves,
}
/// Specifies the function for producing the neutral point of the curve.
pub trait IdPoint {
    fn id_point(curve: EdCurves) -> EdCurvePoint;
}

/// Specifies the function for producing the generator point of the curve.
pub trait Generator {
    fn generator(curve: EdCurves, msb: bool) -> EdCurvePoint;
}

/// Specifies the function for verifying that a point is on the curve.
pub trait IsPoint {
    fn is_point(&self) -> bool;
}

impl Add<&EdCurvePoint> for EdCurvePoint {
    type Output = EdCurvePoint;
    /// # Point Composition
    /// Composes two curve points and returns another curve point. If a point is defined as
    /// = (x, y), then ```Edwards Curve``` point addition is defined as:
    /// * ```(x₁, y₁) + (x₂, y₂)  = (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂), (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)```
    /// * where ```"/"``` is defined to be multiplication by modular inverse.
    /// * Because d is not square in Z/pZ, the strongly
    /// unified Edwards point addition formulas apply. ref:
    /// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
    fn add(mut self, p2: &EdCurvePoint) -> EdCurvePoint {
        let A = (self.z.clone() * p2.z.clone()) % self.p.clone();
        let B = (A.clone() * A.clone()) % self.p.clone();
        let C = (self.x.clone() * p2.x.clone()) % self.p.clone();
        let D = (self.y.clone() * p2.y.clone()) % self.p.clone();
        let E = ((self.d.clone() * C.clone()) * D.clone()) % self.p.clone();
        let F = (B.clone() - E.clone()) % self.p.clone();
        let G = (B.clone() + E.clone()) % self.p.clone();
        let X_3 = (A.clone()
            * F.clone()
            * ((self.x.clone() + self.y.clone()) * (p2.x.clone() + p2.y.clone())
                - C.clone()
                - D.clone()))
            % self.p.clone();
        let Y_3 =
            (A.clone() * G.clone() * (D.clone() - (Integer::from(1) * C.clone()))) % self.p.clone();
        let Z_3 = (F.clone() * G.clone()) % self.p.clone();

        EdCurvePoint {
            x: X_3,
            y: Y_3,
            d: self.d,
            z: Z_3,
            curve: self.curve,
            p: self.p.clone(),
            r: self.r.clone(),
            n: self.n.clone(),
        }
    }
}

impl Clone for EdCurvePoint {
    fn clone(&self) -> EdCurvePoint {
        EdCurvePoint {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
            p: self.p.clone(),
            d: self.d.clone(),
            r: self.r.clone(),
            n: self.n.clone(),
            curve: self.curve,
        }
    }
}

impl Generator for EdCurvePoint {
    /// Returns CurvePoint(x, y), where x is the smallest possible value that satisfies the curve
    /// equation, and y is obtained from solving the curve equation with x.
    /// Any scalar s * G generates the curve.
    /// # Arguments
    ///
    /// * `msb: bool`: selects the y coordinate for corresponding x coordinate.
    ///
    /// # Remark: Generator values are taken from:
    /// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
    fn generator(req_curve: EdCurves, msb: bool) -> EdCurvePoint {
        let x = match req_curve {
            // EdCurves::E222 => Integer::from(18),
            // EdCurves::E382 => Integer::from(7),
            EdCurves::E448 => Integer::from(8),
            // EdCurves::E521 => Integer::from(4),
        };

        EdCurvePoint {
            x: x.clone(),
            y: Integer::from_str_radix(ed_curve_constants::G_Y, 16).unwrap(),
            z: Integer::from(1),
            p: curve_p(req_curve),
            d: curve_d(req_curve),
            r: curve_r(req_curve),
            n: order(req_curve),
            curve: req_curve,
        }
    }
}

impl IdPoint for EdCurvePoint {
    /// Returns the neutral point 𝒪 = (0, 1, 1)
    fn id_point(req_curve: EdCurves) -> EdCurvePoint {
        EdCurvePoint {
            x: Integer::from(0),
            y: Integer::from(1),
            z: Integer::from(1),
            p: curve_p(req_curve),
            d: curve_d(req_curve),
            r: curve_r(req_curve),
            n: order(req_curve),
            curve: req_curve,
        }
    }
}

impl IsPoint for EdCurvePoint {
    /// * Solves curve equation: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
    /// * `return` true if rhs == lhs, false otherwise
    fn is_point(&self) -> bool {
        let x = self.x.clone();
        let y = self.y.clone();
        (x.clone().pow(2) + y.clone().pow(2)) % self.p.clone()
            == (1 + self.d.clone() * x.pow(2) * y.pow(2)) % self.p.clone()
    }
}

impl Mul<Integer> for EdCurvePoint {
    type Output = EdCurvePoint;
    /// Fixed-time point multiplication. NOTE: not memory safe.
    /// * `s`: scalar value to multiply by
    /// * multiplication is defined to be P₀ + P₁ + ... Pₛ
    /// ## Remark:
    /// excessive cloning in this function is a consequence of the
    /// Rug Integer GMP FFI which does not implement ```copy``` trait. Observed complexity
    /// impact appears minimal.
    fn mul(self, s: Integer) -> EdCurvePoint {
        let mut result = EdCurvePoint::id_point(self.curve);
        let mut base = self;

        for i in (0..s.bits()).rev() {
            if s.bit(i) {
                result = result + &base; // Add the current base if the bit is set.
            }
            base = base.clone() + &base; // Always double the base.
        }

        result // result = P * s
    }
}

/// If a point is defined as (x, y) then its negation is (-x, y)
impl Neg for EdCurvePoint {
    type Output = EdCurvePoint;
    fn neg(mut self) -> EdCurvePoint {
        self.x = self.p.clone() - self.x.clone();
        self
    }
}

/// Compares points for equality by coordinate values.
impl PartialEq for EdCurvePoint {
    fn eq(&self, other: &Self) -> bool {
        self.x.eq(&other.x) && self.y.eq(&other.y) && self.z.eq(&other.z)
    }
}

/// The d coefficient for Edwards formulas defines the order of the curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_d(curve: EdCurves) -> Integer {
    match curve {
        EdCurves::E448 => Integer::from(ed_curve_constants::D_448),
    }
}

/// Matches number of points on the curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn order(curve: EdCurves) -> Integer {
    match curve {
        EdCurves::E448 => Integer::from_str_radix(ed_curve_constants::N_448, 16).unwrap(),
    }
}

/// Matches curve modulus 𝑝, a prime defining the finite field 𝔽𝑝.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_p(curve: EdCurves) -> Integer {
    match curve {
        EdCurves::E448 => Integer::from_str_radix(ed_curve_constants::P_448, 16).unwrap(),
    }
}

/// Matches r value for curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_r(curve: EdCurves) -> Integer {
    match curve {
        EdCurves::E448 => Integer::from_str_radix(ed_curve_constants::R_448, 16).unwrap(),
    }
}
