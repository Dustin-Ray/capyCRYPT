extern crate rug;
use crate::E521;
use crate::sha3::aux_functions::arith::mod_formula;
use self::e521_module::{PointOps, get_e521_id_point};

use rug::Integer as big;
use rug::ops::PowAssign;

/// 𝐸₅₂₁ curve (a so-called Edwards curve), is defined by the following parameters:
/// • 𝑝 ≔ 2⁵²¹−1, a Mersenne prime defining the finite field 𝔽𝑝 .
/// • curve equation: 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦² with 𝑑 = −376014. 
pub mod e521_module {
    use crate::E521;
    use super::solve_for_y;
    use rug::{Integer as big, ops::PowAssign};
    
    pub trait PointOps {
        fn sec_mul(&mut self, s: big) -> E521;
        fn add_points(&mut self, other: &E521);}
    
    /// Initializes r value for curve. 
    fn set_r() -> big {
        let mut r = rug::Integer::from(2);
        r.pow_assign(519);
        let s = big::from_str_radix("337554763258501705789107630418782636071904961214051226618635150085779108655765", 10).unwrap();
        r -= s;
        return r;
    }

    /// Initializes curve modulus 𝑝 := 2⁵²¹−1, a Mersenne prime defining the finite field 𝔽𝑝.
    fn set_p() -> big {
        let mut p = big::from(2);
        p.pow_assign(521);
        p -= 1;
        p
    }

    /// Initializes number of points on the curve. 
    pub fn set_n() -> big {
        let mut n = set_r();
        n *= 4;
        return n;
    }

    /// Sets the curve d parameter. 
    fn set_d() -> big { return big::from(-376014);}

    /// Generates the neutral point 𝒪 = (0, 1)
    pub fn get_e521_id_point() -> E521 {
        let point = E521{
            x: rug::Integer::from(0),
            y: rug::Integer::from(1),
            p: set_p(),
            d: set_d(),
            r: set_r(), 
            n: set_n()
        };
        point
    }

    /// Gets point for arbitrary (x, y) TODO verify point is on curve
    pub fn get_e521_point(x: rug::Integer, y: rug::Integer) -> E521 {
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
        let x = rug::Integer::from(4);
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
    fn sec_mul(&mut self, s: rug::Integer) -> E521{
        let mut r0 = get_e521_id_point();
        for i in (0..=s.significant_bits()).rev()  {
            if s.get_bit(i) {
                r0.add_points(&self.clone());
                self.add_points(&self.clone());
            } else { 
                self.add_points(&r0.clone());
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

        let x1 = self.x.clone();
        let y1 = self.y.clone();
        let x2 = p2.x.clone();
        let y2 = p2.y.clone();

        let p = self.p.clone();
        let d = self.d.clone();
        
        // (x₁y₂ + y₁x₂)
        let x1y2 = x1.clone() * y2.clone();
        let x1y2 = mod_formula(x1y2, p.clone());
        let y1x2 = y1.clone() * x2.clone();
        let y1x2 = mod_formula(y1x2, p.clone());
        let x1y2y1x2_sum = x1y2 + y1x2;
        let x1y2y1x2_sum = mod_formula(x1y2y1x2_sum, p.clone());

        // 1 / (1 + dx₁x₂y₁y₂)
        let one_plus_dx1x2y1y2 = big::from(1) + (d.clone() * x1.clone() * x2.clone() * y1.clone() * y2.clone());
        let one_plus_dx1x2y1y2 = mod_formula(one_plus_dx1x2y1y2, p.clone());
        let one_plus_dx1x2y1y2inv = mod_inv(&one_plus_dx1x2y1y2, &p.clone());

        // (y₁y₂ − x₁x₂)
        let y1y2x1x2_difference = (y1.clone() * y2.clone()) - (x1.clone() * x2.clone());
        let y1y2x1x2_difference = mod_formula(y1y2x1x2_difference, p.clone());

        // 1 / (1 − dx₁x₂y₁y₂)
        let one_minus_dx1x2y1y2 = big::from(1) - (d * x1 * x2 * y1 * y2);
        let one_minus_dx1x2y1y2 = mod_formula(one_minus_dx1x2y1y2, p.clone());
        let one_minus_dx1x2y1y2inv = mod_inv(&one_minus_dx1x2y1y2, &p);

        // (x₁y₂ + y₁x₂) / (1 + dx₁x₂y₁y₂)
        let new_x = x1y2y1x2_sum * one_plus_dx1x2y1y2inv;
        let new_x = mod_formula(new_x, p.clone());

        // (y₁y₂ − x₁x₂) / (1 − dx₁x₂y₁y₂)
        let new_y = y1y2x1x2_difference * one_minus_dx1x2y1y2inv;
        let new_y = mod_formula(new_y, p);

        self.x = new_x;
        self.y = new_y;

    }
}

    /// Solves for y in curve equation 𝑥² + 𝑦² = 1 + 𝑑𝑥²𝑦²
    fn solve_for_y(x: &big, p: big, msb: bool) -> big {
        let mut sq = x.clone();
        sq.pow_assign(2);
        let num = big::from(1) - sq.clone();
        let num = mod_formula(num, p.clone());
        let denom = big::from(376014) * sq + big::from(1);
        let denom = mod_formula(denom, p.clone());
        let denom = mod_inv(&denom, &p);
        let radicand = num * denom;
        let y = sqrt(&radicand, p, msb);
        y
    }

    /// Compute a square root of v mod p with a specified
    /// least significant bit, if such a root exists.
    /// * `v`: big value to compute square root for
    /// * `p`: big curve modulus
    /// * `lsb`: each x has 2 `y` values on curve, lsb selects which `y` value to use
    pub fn sqrt(v: &big, p: big, lsb: bool) -> big {
        if v.clone().signum() == 0 { return big::from(0); }
        let r = v.clone().secure_pow_mod(&((p.clone() >> 2) + 1), &p);
        if !r.get_bit(0).eq(&lsb) {
            let new_r = &p - r; // correct the lsb
            let borrowed_r = new_r.clone();
            let return_r = new_r.clone();
            let bi = mod_formula(new_r * borrowed_r - v, p);
            if bi.signum() == 0 {
                return return_r;
            } else { return big::from(0); }
        } r
    }




    /// Performs modular inverse via euclidian algorithm.
    /// * `n`: big value to mod
    /// * `p`: modulus
    pub fn mod_inv(n: &big, p: &big) -> big {
        if p.eq(&big::ZERO) { return big::ZERO }
        let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), big::ZERO, big::from(1));
        while a < big::ZERO { a += p }
        while a > big::from(1) {
            let (div, rem) = a.div_rem(m.clone());
            inv -= div * &x;
            a = rem;
            std::mem::swap(&mut a, &mut m);
            std::mem::swap(&mut x, &mut inv);
        }
        if inv < big::ZERO { inv += p }
        inv
    }

