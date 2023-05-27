extern crate rug;
use rug::ops::{Pow, PowAssign};
use rug::Integer;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Neg;
use std::rc::Rc;

#[derive(Debug, Clone, Copy)]
pub enum Curves {
    E222,
    E382,
    E448,
    E521,
}

/// d, n, p, and r values for each curve
mod curve_constants {
    pub const D_521: i32 = -376014;
    pub const N_521: &str = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF456DB191D1BF217DCDAE2BD79FB14FC13EF63115A6A3C7D1503A890D7D46035AC";
    pub const P_521: &str = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    pub const R_521: &str = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD15B6C64746FC85F736B8AF5E7EC53F04FBD8C4569A8F1F4540EA2435F5180D6B";

    pub const D_448: i32 = -39081;
    pub const N_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDF3288FA7113B6D26BB58DA4085B309CA37163D548DE30A4AAD6113CC";
    pub const P_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    pub const R_448: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";

    pub const D_382: i32 = -67254;
    pub const N_382: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF57EC87C87A57BB85F179A4A06C40B49DCF89F84FF4F25C64";
    pub const P_382: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF97";
    pub const R_382: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD5FB21F21E95EEE17C5E69281B102D2773E27E13FD3C9719";

    pub const D_222: i32 = 160102;
    pub const N_222: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFDC32F257A4CBE00BCC508D6632FC";
    pub const P_222: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8B";
    pub const R_222: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF70CBC95E932F802F31423598CBF";
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
/// ## Supported Curves:
/// This library supports multiple curves of Edwards form which can be used interchangebly
/// with supported model functionality. Current supported curves are:
/// * E222
/// * E382
/// * E448
/// * E521
/// ## Security claims
/// A comparison of security provided by each curve is made in <https://eprint.iacr.org/2013/647.pdf>
pub struct CurvePoint {
    pub x: Integer,
    pub y: Integer,
    pub p: Integer,
    pub d: Integer,
    pub r: Integer,
    pub n: Integer,
    pub curve: Curves,
}
/// Specifies the function for producing the neutral point of the curve.
pub trait IdPoint {
    fn id_point(curve: Curves) -> CurvePoint;
}

/// Specifies the function for producing the generator point of the curve.
pub trait Generator {
    fn generator(curve: Curves, msb: bool) -> CurvePoint;
}

/// Specifies the function for producing any point of the curve.
pub trait Point {
    fn point(curve: Curves, x: rug::Integer, y: rug::Integer) -> CurvePoint;
}

/// Specifies the function for verifying that a point is on the curve.
pub trait IsPoint {
    fn is_point(&self) -> bool;
}

/// # Point Composition
/// Composes two curve points and returns another curve point. If a point is defined as
/// = (x, y), then ```Edwards Curve``` point addition is defined as:
/// * ```(x₁, y₁) + (x₂, y₂)  = (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂), (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)```
/// * where ```"/"``` is defined to be multiplication by modular inverse.
/// * The Edwards curve point composition procedure is guaranteed to deliver a point on the curve,
/// differing from curves in Weierstrass form which require different composition formulas for different
/// point values. In particular, because d is not square in Z/pZ, the strongly
/// unified Edwards point addition formulas apply. ref:
/// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
/// # Usage
///
///
impl Add<CurvePoint> for CurvePoint {
    type Output = CurvePoint;

    fn add(self, p2: CurvePoint) -> CurvePoint {
        let x1 = Rc::new(&self.x);
        let y1 = Rc::new(&self.y);
        let x2 = p2.x.clone();
        let y2 = p2.y;

        let p = self.p.clone();
        let d = self.d.clone();

        // (x₁y₂ + y₁x₂)
        let x1y2 = (*x1.clone() * y2.clone()) % p.clone();
        let y1x2 = (*y1.clone() * x2.clone()) % p.clone();
        let x1y2y1x2_sum = (x1y2 + y1x2) % p.clone();
        // 1 / (1 + dx₁x₂y₁y₂)
        let one_plus_dx1x2y1y2 = (Integer::from(1)
            + (d.clone() * *x1.clone() * x2.clone() * *y1.clone() * y2.clone()))
            % p.clone();
        let one_plus_dx1x2y1y2inv = mod_inv(&one_plus_dx1x2y1y2, &p);
        // (y₁y₂ − x₁x₂)
        let y1y2x1x2_difference =
            ((*y1.clone() * y2.clone()) - (*x1.clone() * x2.clone())) % p.clone();
        // 1 / (1 − dx₁x₂y₁y₂)
        let one_minus_dx1x2y1y2 = (Integer::from(1) - (d * *x1 * x2 * *y1 * y2)) % p.clone();
        let one_minus_dx1x2y1y2inv = mod_inv(&one_minus_dx1x2y1y2, &p);
        // (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂)
        let new_x = ((x1y2y1x2_sum * one_plus_dx1x2y1y2inv) % p.clone() + p.clone()) % p.clone();
        // (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)
        let new_y = ((y1y2x1x2_difference * one_minus_dx1x2y1y2inv) % p.clone() + p.clone()) % p;
        CurvePoint::point(self.curve, new_x, new_y)
    }
}

impl Clone for CurvePoint {
    fn clone(&self) -> CurvePoint {
        CurvePoint {
            x: self.x.clone(),
            y: self.y.clone(),
            p: self.p.clone(),
            d: self.d.clone(),
            r: self.r.clone(),
            n: self.n.clone(),
            curve: self.curve,
        }
    }
}

impl Generator for CurvePoint {
    /// Returns CurvePoint(x, y), where x is provided and y is obtained from curve equation.
    /// Any scalar s * G generates the curve.
    /// # Arguments
    ///
    /// * `msb: bool`: selects the y coordinate for corresponding x coordinate.
    ///
    /// # Usage
    ///
    fn generator(req_curve: Curves, msb: bool) -> CurvePoint {
        let x = match req_curve {
            Curves::E222 => Integer::from(18),
            Curves::E382 => Integer::from(7),
            Curves::E448 => Integer::from(8),
            Curves::E521 => Integer::from(4),
        };

        CurvePoint {
            x: x.clone(),
            y: solve_for_y(&x, curve_p(req_curve), curve_d(req_curve), msb),
            p: curve_p(req_curve),
            d: curve_d(req_curve),
            r: curve_r(req_curve),
            n: curve_n(req_curve),
            curve: req_curve,
        }
    }
}

/// Returns the neutral point 𝒪 = (0, 1)
impl IdPoint for CurvePoint {
    fn id_point(req_curve: Curves) -> CurvePoint {
        CurvePoint {
            x: Integer::from(0),
            y: Integer::from(1),
            p: curve_p(req_curve),
            d: curve_d(req_curve),
            r: curve_r(req_curve),
            n: curve_n(req_curve),
            curve: req_curve,
        }
    }
}

/// * Solves curve equation: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
/// * `return` true if rhs == lhs, false otherwise
impl IsPoint for CurvePoint {
    fn is_point(&self) -> bool {
        let x = self.x.clone();
        let y = self.y.clone();
        (x.clone().pow(2) + y.clone().pow(2)) % self.p.clone()
            == (1 + self.d.clone() * x.pow(2) * y.pow(2)) % self.p.clone()
    }
}

/// Fixed-time point multiplication. NOTE not memory safe afaik.
/// * `s`: scalar value to multiply by
/// * multiplication is defined to be P₀ + P₁ + ... Pₛ
impl Mul<Integer> for CurvePoint {
    type Output = CurvePoint;

    fn mul(self, s: Integer) -> CurvePoint {
        let mut r0 = CurvePoint::id_point(self.curve);
        let mut r1 = self;
        for i in (0..=s.significant_bits()).rev() {
            if s.get_bit(i) {
                r0 = r0 + r1.clone();
                r1 = r1.clone() + r1.clone();
            } else {
                r1 = r0.clone() + r1;
                r0 = r0.clone() + r0.clone();
            }
        }
        r0 // r0 = P * s
    }
}

/// If a point is defined as (x, y) then its negation is (-x, y)
impl Neg for CurvePoint {
    type Output = CurvePoint;
    fn neg(self) -> CurvePoint {
        CurvePoint::point(self.curve, self.p - self.x, self.y)
    }
}

/// Compares points for equality by coordinate values.
impl PartialEq for CurvePoint {
    fn eq(&self, other: &Self) -> bool {
        self.x.eq(&other.x) && self.y.eq(&other.y)
    }
}

/// Returns CurvePoint(x, y) for any x, y. Assumes valid curve point.
///
/// # Arguments
///
/// * `x: rug::Integer`     x-coordinate for point.
/// * `y: rug::Integer`     y-coordinate for point.
///
/// # Examples
impl Point for CurvePoint {
    fn point(req_curve: Curves, x: Integer, y: Integer) -> CurvePoint {
        CurvePoint {
            x,
            y,
            p: curve_p(req_curve),
            d: curve_d(req_curve),
            r: curve_r(req_curve),
            n: curve_n(req_curve),
            curve: req_curve,
        }
    }
}

/// Performs modular inverse via euclidian algorithm.
/// * `n`: Integer value to mod
/// * `p`: modulus
fn mod_inv(n: &Integer, p: &Integer) -> Integer {
    if p.eq(&Integer::ZERO) {
        return Integer::ZERO;
    }
    let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), Integer::ZERO, Integer::from(1));
    while a < Integer::ZERO {
        a += p
    }
    while a > 1 {
        let (div, rem) = a.div_rem(m.clone());
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }
    if inv < Integer::ZERO {
        inv += p
    }
    inv
}

/// The d coefficient for Edwards formulas defines the order of the curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_d(curve: Curves) -> Integer {
    match curve {
        Curves::E222 => Integer::from(curve_constants::D_222),
        Curves::E382 => Integer::from(curve_constants::D_382),
        Curves::E448 => Integer::from(curve_constants::D_448),
        Curves::E521 => Integer::from(curve_constants::D_521),
    }
}

/// Initializes number of points on the curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_n(curve: Curves) -> Integer {
    match curve {
        Curves::E222 => Integer::from_str_radix(curve_constants::N_222, 16).unwrap(),
        Curves::E382 => Integer::from_str_radix(curve_constants::N_382, 16).unwrap(),
        Curves::E448 => Integer::from_str_radix(curve_constants::N_448, 16).unwrap(),
        Curves::E521 => Integer::from_str_radix(curve_constants::N_521, 16).unwrap(),
    }
}

/// Initializes curve modulus 𝑝, a prime defining the finite field 𝔽𝑝.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_p(curve: Curves) -> Integer {
    match curve {
        Curves::E222 => Integer::from_str_radix(curve_constants::P_222, 16).unwrap(),
        Curves::E382 => Integer::from_str_radix(curve_constants::P_382, 16).unwrap(),
        Curves::E448 => Integer::from_str_radix(curve_constants::P_448, 16).unwrap(),
        Curves::E521 => Integer::from_str_radix(curve_constants::P_521, 16).unwrap(),
    }
}

/// Initializes r value for curve.
/// <https://eprint.iacr.org/2013/647.pdf>
pub fn curve_r(curve: Curves) -> Integer {
    match curve {
        Curves::E222 => Integer::from_str_radix(curve_constants::R_222, 16).unwrap(),
        Curves::E382 => Integer::from_str_radix(curve_constants::R_382, 16).unwrap(),
        Curves::E448 => Integer::from_str_radix(curve_constants::R_448, 16).unwrap(),
        Curves::E521 => Integer::from_str_radix(curve_constants::R_521, 16).unwrap(),
    }
}

/// Solves for y in curve equation 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
fn solve_for_y(x: &Integer, p: Integer, d: Integer, msb: bool) -> Integer {
    let mut sq = x.clone();
    sq.pow_assign(2);
    let num = Integer::from(1) - sq.clone();
    let num = num % p.clone();
    let denom = -d * sq + Integer::from(1);
    let denom = denom % p.clone();
    let denom = mod_inv(&denom, &p);
    let radicand = num * denom;
    sqrt(&radicand, p, msb)
}

/// Compute a square root of v mod p with a specified
/// least significant bit, if such a root exists.
/// * `v`: Integer value to compute square root for
/// * `p`: Integer curve modulus
/// * `lsb`: each x has 2 `y` values on curve, lsb selects which `y` value to use
fn sqrt(v: &Integer, p: Integer, lsb: bool) -> Integer {
    if v.clone().signum() == 0 {
        return Integer::from(0);
    }
    let r = v.clone().secure_pow_mod(&((p.clone() >> 2) + 1), &p);
    if !r.get_bit(0).eq(&lsb) {
        let new_r = &p - r; // correct the lsb
        let borrowed_r = new_r.clone();
        let return_r = new_r.clone();
        let bi = (new_r * borrowed_r - v) % p;
        if bi.signum() == 0 {
            return return_r;
        } else {
            return Integer::from(0);
        }
    }
    r
}
