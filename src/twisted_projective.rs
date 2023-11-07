use crypto_bigint::{
    impl_modulus,
    modular::{constant_mod::ResidueParams, montgomery_reduction},
    Uint, U448, U896,
};
use std::ops::{Add, Mul, Neg};

/// All curves defined here:
/// <https://csrc.nist.gov/publications/detail/fips/186/5/final>
#[derive(Debug, Clone, Copy)]
pub enum EdCurves {
    E222,
    E382,
    E448,
}

impl EdCurves {
    pub const D_448: u64 = 39081; //negative
    pub const N_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDF3288FA7113B6D26BB58DA4085B309CA37163D548DE30A4AAD6113CC";
    pub const P_448: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    pub const R_448: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";

    pub const D_382: i32 = 67254; // negative
    pub const N_382: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF57EC87C87A57BB85F179A4A06C40B49DCF89F84FF4F25C64";
    pub const P_382: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF97";
    pub const R_382: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD5FB21F21E95EEE17C5E69281B102D2773E27E13FD3C9719";

    pub const D_222: i32 = 160102; //positve
    pub const N_222: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFDC32F257A4CBE00BCC508D6632FC";
    pub const P_222: &str = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8B";
    pub const R_222: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF70CBC95E932F802F31423598CBF";

}

#[derive(Debug, Clone, Copy)]
pub struct EdwardsPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub d: FieldElement,
    pub z: FieldElement,
    pub curve: EdCurves,
}

impl_modulus!(
    Modulus,
    U448,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
);

/// Specifies the function for producing the neutral point of the curve.
pub trait IdPoint {
    fn id_point(curve: EdCurves) -> EdwardsPoint;
}

impl EdwardsPoint {
    // Converts projective coordinates to affine coordinates (x, y)
    fn to_affine(&self) -> EdwardsPoint {
        let z_inv = self.z.invert();
        let x_affine = FieldElement {
            val: montgomery_reduction(
                &self.x.val.mul_wide(&z_inv.val),
                &Modulus::MODULUS,
                Modulus::MOD_NEG_INV,
            ),
        };

        let y_affine = FieldElement {
            val: montgomery_reduction(
                &self.y.val.mul_wide(&z_inv.val),
                &Modulus::MODULUS,
                Modulus::MOD_NEG_INV,
            ),
        };

        EdwardsPoint {
            x: x_affine,
            y: y_affine,
            d: self.d,
            z: FieldElement { val: U448::ONE },
            curve: self.curve,
        }
    }
}

/// If a point is defined as (x, y) then its negation is (-x, y)
impl Neg for EdwardsPoint {
    type Output = EdwardsPoint;
    fn neg(mut self) -> EdwardsPoint {
        self.x = FieldElement {
            val: Modulus::MODULUS.sub_mod(&self.x.val, &Modulus::MODULUS),
        };
        self
    }
}

impl IdPoint for EdwardsPoint {
    /// Returns the neutral point 𝒪 = (0, 1)
    fn id_point(req_curve: EdCurves) -> EdwardsPoint {
        EdwardsPoint {
            x: FieldElement::from(0),
            y: FieldElement::from(1),
            z: FieldElement::from(1),
            d: FieldElement::from(0),
            curve: req_curve,
        }
    }
}

impl Add<&EdwardsPoint> for EdwardsPoint {
    type Output = EdwardsPoint;
    fn add(self, p2: &EdwardsPoint) -> EdwardsPoint {
        let a = self.z.mul(&p2.z);

        let b = a.mul(&a);
        let c = self.x.mul(&p2.x);
        let d = self.y.mul(&p2.y);
        let e = self.d.mul(&c).mul(&d);
        let f = b.sub(&e);
        let g = b.add(&e);
        // A * F * ((X1+Y1) * (X2 + Y2) - C - D)
        let x_3 = a
            .mul(&f)
            .mul(&self.x.add(&self.y))
            .mul(&(p2.x.add(&p2.y)).sub(&c).sub(&d));
        // A * G * (D - 1C)
        let y_3 = a.mul(&g).mul(&(d.sub(&c)));
        // F * G
        let z_3 = f.mul(&g);

        EdwardsPoint {
            x: x_3,
            y: y_3,
            d: self.d,
            z: z_3,
            curve: self.curve,
        }
    }
}

impl<const LIMBS: usize> Mul<Uint<LIMBS>> for EdwardsPoint {
    type Output = EdwardsPoint;

    fn mul(self, s: Uint<LIMBS>) -> EdwardsPoint {
        let mut r0 = EdwardsPoint::id_point(self.curve);
        let mut r1 = self;

        for i in (0..s.bits()).rev() {
            if s.bit(i as usize).into() {
                r0 = r0 + &r1;
                r1 = r1 + &r1;
            } else {
                r1 = r0 + &r1;
                r0 = r0 + &r0;
            }
        }
        r0 // r0 = P * s
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FieldElement {
    pub val: U448,
}

impl FieldElement {
    // Assume these methods exist for the FieldElement structure
    fn add(&self, other: &Self) -> Self {
        FieldElement {
            val: self.val.add_mod(&other.val, &Modulus::MODULUS),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        FieldElement {
            val: self.val.sub_mod(&other.val, &Modulus::MODULUS),
        }
    }

    fn mul(&self, other: &Self) -> Self {
        FieldElement {
            val: montgomery_reduction(
                &self.val.mul_wide(&other.val),
                &Modulus::MODULUS,
                Modulus::MOD_NEG_INV,
            ),
        }
    }

    fn from(num: u64) -> Self {
        FieldElement {
            val: U448::from(num as u64),
        }
    }

    fn invert(&self) -> Self {
        FieldElement {
            val: self.val.inv_mod(&Modulus::MODULUS).0,
        }
    }

    fn to_affine(&self) -> Self {
        let z_inv = self.invert(); // Calculate the modular inverse
        FieldElement {
            val: montgomery_reduction(
                &self.val.mul_wide(&z_inv.val),
                &Modulus::MODULUS,
                Modulus::MOD_NEG_INV,
            ),
        }
    }
}





#[test]
fn test_generator() {
    let g_x = FieldElement {
        val: U448::from(8_u64),
    };
    let g_y = FieldElement{val: U448::from_be_hex("C66F6F0565E6D0B5F2BB263CEBB9F8540EB046F40ED0FFF7F84D84653B428D989AABFF93B6BF700801228094E3DD0C2D1C600E3B0BCCFC32")};


    let g_d = FieldElement {
        val: Modulus::MODULUS.sub_mod(&U448::from(EdCurves::D_448), &Modulus::MODULUS),
    };
    let r0 = EdwardsPoint::id_point(EdCurves::E448);
    let g = EdwardsPoint {
        x: g_x,
        y: g_y,
        d: g_d,
        z: FieldElement { val: U448::ONE },
        curve: EdCurves::E448,
    };

    println!("g x val: {:}", g.x.val);
    println!("g y val: {:}", g.y.val);

    let g_inv = -g;

    println!("g_inv x val: {:}", g_inv.x.val);
    println!("g_inv y val: {:}", g_inv.y.val);

    let res = g + &g_inv;

    println!("res x val: {:}", res.x.val);
    println!("res y val: {:}", res.y.val);
}

#[test]
pub fn test_u448() {
    let a = U448::from(5_u64);
    let b = U448::from(3_u64);

    let d = montgomery_reduction(&a.mul_wide(&b), &Modulus::MODULUS, Modulus::MOD_NEG_INV);

    println!("c.0: {:?}", d);
}
