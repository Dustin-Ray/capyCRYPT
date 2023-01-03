use std::ops::{Mul, Sub};
use num::{BigInt, Integer, Zero, One};
use num_bigint::Sign;
use crate::E521;
use self::e521::{PointOps, get_e521_id_point};

pub mod e521 {
    use std::{str::FromStr, ops::{Sub}};
    use num_bigint::{BigInt};
    use crate::E521;
    use super::solve_for_y;
    
    pub trait PointOps {
        fn sec_mul(&mut self, s: BigInt) -> E521;
        fn add_points(&mut self, other: &E521); }
    
    /// 𝐸₅₂₁ curve (a so-called Edwards curve), is defined by the following parameters:
    /// • 𝑝 ≔ 2⁵²¹−1, a Mersenne prime defining the finite field 𝔽𝑝 .
    /// • curve equation: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦² with 𝑑 = −376014. 
    
    /// Initializes r value for curve. 
    fn set_r() -> BigInt {
        let r = BigInt::from(2);
        let r = r.pow(519);
        let s = BigInt::from_str("337554763258501705789107630418782636071904961214051226618635150085779108655765").unwrap();
        let r = r.sub(s);
        return r;
    }

    /// Initializes curve modulus 𝑝 := 2⁵²¹−1, a Mersenne prime defining the finite field 𝔽𝑝.
    fn set_p() -> BigInt {
        let p = BigInt::from(2);
        let p = p.pow(521);
        let p = p - 1;
        return p;
    }

    /// Initializes number of points on the curve. 
    pub fn set_n() -> BigInt {
        let n = set_r();
        let n = n * &BigInt::from(4);
        return n;
    }

    /// Sets the curve d parameter. 
    fn set_d() -> BigInt { return Some(BigInt::from(-376014)).unwrap();}

    /// Generates the neutral point 𝒪 = (0, 1)
    pub fn get_e521_id_point() -> E521 {
        let point = E521{
            x: BigInt::from(0),
            y: BigInt::from(1),
            p: set_p(),
            d: set_d(),
            r: set_r(), 
            n: set_n()
        };
        point
    }

    /// Gets point for arbitrary (x, y) TODO verify point is on curve
    pub fn get_e521_point(x: BigInt, y: BigInt) -> E521 {
        let point = E521{
            x,
            y,
            p: set_p(),
            d: set_d(),
            r: set_r(), 
            n: set_n()
        };
        point
    }

    /// Gets point for arbitrary (x, y) TODO verify point is on curve
    pub fn get_e521_gen_point(msb: bool) -> E521 {
        let x = BigInt::from(4);
        let new_x = x.clone();
        let point = E521{
            x,
            y: solve_for_y(&new_x, set_p(), msb),
            p: set_p(),
            d: set_d(),
            r: set_r(), 
            n: set_n()
        };
        point
    }

    /// If a point is defined as (x, y) then its negation is (-x, y)
    pub fn negate_point(p: &E521) -> E521 {
        let x = p.x.clone();
        let y = p.y.clone();
        let x = x * -1;
        let point = get_e521_point(x, y);
        point
    }

    // Compare points for equality by coordinate values only.
    pub fn e521_equals(p1: &E521, p2: &E521) -> bool { p1.x == p2.x && p1.y == p2.y }
 
}

///Definitions for addition and multiplcation on the curve
impl PointOps for E521{

    /// Constant time multiplication NOTE not memory safe afaik.
    /// * multiplication is defined to be P + P + P .... s times
    fn sec_mul(&mut self, s: BigInt) -> E521{
        let mut r0 = get_e521_id_point();
        for i in (0..=s.bits()).rev()  {
            if s.bit(i) {
                r0.add_points(&self.clone());
                self.add_points(&self.clone());
            } else { 
                self.add_points(&r0);
                r0.add_points(&r0.clone());
            }
        } 
        self.x = r0.x;
        self.y = r0.y;
        self.clone()
    }

    /// Adds two E521 points and returns another E521 curve point. If a point is defined as
    /// ```E521``` = (x, y), then ```E521``` addition is defined as:
    /// * (x₁, y₁) + (x₂, y₂)  = (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂), (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)
    /// * where ```"/"``` is defined to be multiplication by modular inverse.
    fn add_points(&mut self, p2: &E521) {

        let p = self.p.clone();
        let d = self.d.clone();

        let x1 = self.x.clone();
        let y1 = self.y.clone();

        // (x₁y₂ + y₁x₂)
        let x1y2 = (x1 * &p2.y).mod_floor(&p);
        let y1x2 = (y1 * &p2.x).mod_floor(&p);
        let x1y2y1x2_sum = (x1y2 + y1x2).mod_floor(&p);

        let x1 = self.x.clone();

        // 1 / (1 + dx₁x₂y₁y₂)
        let one_plus_dx1x2y1y2 = (BigInt::from(1) + (d * x1 * &p2.x * &self.y * &p2.y)).mod_floor(&p);
        let one_plus_dx1x2y1y2inv = mod_inv(&one_plus_dx1x2y1y2, &p);

        let x1 = self.x.clone();
        let y1 = self.y.clone();

        // (y₁y₂ − x₁x₂)
        let y1y2x1x2_difference = ((y1 * &p2.y) - (x1 * &p2.x)).mod_floor(&p);

        let x1 = self.x.clone();
        let d = self.d.clone();

        // 1 / (1 − dx₁x₂y₁y₂)
        let one_minus_dx1x2y1y2 = (BigInt::from(1) - (d * x1 * &p2.x * &self.y * &p2.y)).mod_floor(&p);
        let one_minus_dx1x2y1y2inv = mod_inv(&one_minus_dx1x2y1y2, &p);

        // (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂)
        let new_x = (x1y2y1x2_sum * one_plus_dx1x2y1y2inv).mod_floor(&p);

        // (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)
        let new_y = (y1y2x1x2_difference * one_minus_dx1x2y1y2inv).mod_floor(&p);
        self.x = new_x;
        self.y = new_y;

    }
}

    /// Solves for y in curve equation 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
    fn solve_for_y(x: &BigInt, p: BigInt, msb: bool) -> BigInt {
        let num = BigInt::from(1) - x.pow(2);
        let num = mod_formula(&num, &p);
        let denom = BigInt::from(376_014) * x.pow(2) + BigInt::from(1);
        let denom = mod_formula(&denom, &p);
        let denom = mod_inv(&denom, &p);
        let radicand = num * denom;
        let y = sqrt(&radicand, p, msb);
        y
    }

    /// Compute a square root of v mod p with a specified
    /// least significant bit, if such a root exists.
    /// * `v`: BigInt value to compute square root for
    /// * `p`: BigInt curve modulus
    /// * `lsb`: each x has 2 `y` values on curve, lsb selects which `y` value to use
    pub fn sqrt(v: &BigInt, p: BigInt, lsb: bool) -> BigInt {
        if v.sign() ==  Sign::NoSign{ return BigInt::from(0); }
        let r = v.modpow(&((p.clone() >> 2) + 1), &p);
        if !r.bit(0).eq(&lsb) {
            let new_r = &p - r; // correct the lsb
            let borrowed_r = new_r.clone();
            let return_r = new_r.clone();
            let bi = mod_formula(&new_r.mul(borrowed_r).sub(v), &p);
            if bi.sign() == Sign::NoSign {
                return return_r;
            } else { return BigInt::from(0); }
        } r
    }

    /// Performs BigInt modular arithematic.
    pub fn mod_formula(a: &BigInt, b: &BigInt) -> BigInt { ((a % b) + b) % b }

    /// Performs modular inverse via euclidian algorithm.
    /// * `n`: BigInt value to mod
    /// * `p`: modulus
    pub fn mod_inv(n: &BigInt, p: &BigInt) -> BigInt {
        if p.is_one() { return BigInt::one() }
        let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());
        while a < BigInt::zero() { a += p }
        while a > BigInt::one() {
            let (div, rem) = a.div_rem(&m);
            inv -= div * &x;
            a = rem;
            std::mem::swap(&mut a, &mut m);
            std::mem::swap(&mut x, &mut inv);
        }
        if inv < BigInt::zero() { inv += p }
        inv
    }

