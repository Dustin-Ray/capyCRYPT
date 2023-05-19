extern crate rug;
use rug::ops::{Pow, PowAssign};
use rug::Integer;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Neg;
use std::rc::Rc;

/// Edwards 521 curve
#[derive(Default, Debug)]
pub struct E521 {
    pub x: Integer, //x-coord
    pub y: Integer, //y coord
    pub p: Integer, //prime defining finite field
    pub d: Integer, //d param for curve
    pub r: Integer, //order of curve
    pub n: Integer, //number of points
}
//////////////
/// TRAITS ///
//////////////
pub trait IdPoint {
    fn id_point() -> E521;
}

pub trait Generator {
    fn generator(msb: bool) -> E521;
}

pub trait Point {
    fn point(x: rug::Integer, y: rug::Integer) -> E521;
}

pub trait IsPoint {
    fn is_point(&self) -> bool;
}

impl Add<E521> for E521 {
    type Output = E521;
    /// Adds two E521 points and returns another E521 curve point. If a point is defined as
    /// ```E521``` = (x, y), then ```E521``` addition is defined as:
    /// * (x₁, y₁) + (x₂, y₂)  = (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂), (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)
    /// * where ```"/"``` is defined to be multiplication by modular inverse.
    
    fn add(self, p2: E521) -> E521 {
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
        E521::point(new_x, new_y)
    }
}

impl Clone for E521 {
    fn clone(&self) -> E521 {
        E521 {
            x: self.x.clone(),
            y: self.y.clone(),
            p: self.p.clone(),
            d: self.d.clone(),
            r: self.r.clone(),
            n: self.n.clone(),
        }
    }
}

impl Generator for E521 {
    fn generator(msb: bool) -> E521 {
        let x = Integer::from(4);
        let new_x = x.clone();
        E521 {
            x,
            y: solve_for_y(&new_x, set_p(), msb),
            p: set_p(),
            d: set_d(),
            r: set_r(),
            n: get_n(),
        }
    }
}

impl IdPoint for E521 {
    /// Returns the neutral point 𝒪 = (0, 1)
    fn id_point() -> E521 {
        E521 {
            x: Integer::from(0),
            y: Integer::from(1),
            p: set_p(),
            d: set_d(),
            r: set_r(),
            n: get_n(),
        }
    }
}

impl IsPoint for E521 {
    /// * Solves curve equation: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦² with 𝑑 = −376014
    /// * `v`: key to check
    /// * `return` true if rhs == lhs, false otherwise
    fn is_point(&self) -> bool {
        let x = self.x.clone();
        let y = self.y.clone();
        (x.clone().pow(2) + y.clone().pow(2)) % self.p.clone()
            == (1 + self.d.clone() * x.pow(2) * y.pow(2)) % self.p.clone()
    }
}

impl Mul<Integer> for E521 {
    type Output = E521;
    /// Constant time multiplication NOTE not memory safe afaik.
    /// * `s`: scalar value to multiply by
    /// * multiplication is defined to be P₀ + P₁ + ... Pₛ
    fn mul(self, s: Integer) -> E521 {
        let mut r0 = E521::id_point();
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

impl Neg for E521 {
    type Output = E521;
    /// If a point is defined as (x, y) then its negation is (-x, y)
    fn neg(self) -> E521 {
        let x = self.x.clone();
        let y = self.y.clone();
        let x = x * -1;
        E521::point(x, y)
    }
}

/// Compare points for equality by coordinate values only.
impl PartialEq for E521 {
    fn eq(&self, other: &Self) -> bool {
        self.x.eq(&other.x) && self.y.eq(&other.y)
    }
}

impl Point for E521 {
    /// Returns E521(x, y) for any x, y. Assumes valid curve point.
    ///
    /// # Arguments
    ///
    /// * `x: rug::Integer`     x-coordinate for point.
    /// * `y: rug::Integer`     y-coordinate for point.
    ///
    /// # Examples
    ///
    /// ```
    /// use rug::Integer;
    /// use capycrypt::curve::e521::{Point, E521, IdPoint,};
    /// let point = E521::point(Integer::from(0), Integer::from(1));
    /// assert_eq!(point == E521::id_point(), true);
    /// ```
    fn point(x: Integer, y: Integer) -> E521 {
        E521 {
            x,
            y,
            p: set_p(),
            d: set_d(),
            r: set_r(),
            n: get_n(),
        }
    }
}

/// Initializes number of points on the curve.
pub fn get_n() -> Integer {
    let mut n = set_r();
    n *= 4;
    n
}

/// Performs modular inverse via euclidian algorithm.
/// * `n`: Integer value to mod
/// * `p`: modulus
pub fn mod_inv(n: &Integer, p: &Integer) -> Integer {
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

/// Sets the curve d parameter.
fn set_d() -> Integer {
    Integer::from(-376014)
}

/// Initializes curve modulus 𝑝 := 2⁵²¹−1, a Mersenne prime defining the finite field 𝔽𝑝.
fn set_p() -> Integer {
    let mut p = Integer::from(2);
    p.pow_assign(521);
    p -= 1;
    p
}

/// Initializes r value for curve.
pub fn set_r() -> Integer {
    let mut r = rug::Integer::from(2);
    r.pow_assign(519);
    let s = Integer::from_str_radix(
        "337554763258501705789107630418782636071904961214051226618635150085779108655765",
        10,
    )
    .unwrap();
    r -= s;
    r
}

/// Solves for y in curve equation 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
fn solve_for_y(x: &Integer, p: Integer, msb: bool) -> Integer {
    let mut sq = x.clone();
    sq.pow_assign(2);
    let num = Integer::from(1) - sq.clone();
    let num = num % p.clone();
    let denom = Integer::from(376014) * sq + Integer::from(1);
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
pub fn sqrt(v: &Integer, p: Integer, lsb: bool) -> Integer {
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
