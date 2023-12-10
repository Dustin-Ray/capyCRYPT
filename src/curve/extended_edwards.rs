#![allow(non_snake_case)]
use super::{
    extensible_edwards::ExtensibleCurvePoint,
    field::{field_element::FieldElement, lookup_table::LookupTable, scalar::Scalar},
};
use crypto_bigint::{
    impl_modulus,
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq},
    U448,
};
use fiat_crypto::p448_solinas_64::*;
use std::ops::{Mul, Neg};

impl_modulus!(
    Modulus,
    U448,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
);

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

#[derive(Debug, Clone, Copy)]
pub struct ExtendedPoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

pub struct AffinePoint {
    pub X: FieldElement,
    pub Y: FieldElement,
}

impl ExtendedPoint {
    // https://www.shiftleft.org/papers/isogeny/isogeny.pdf
    // page 4 specifies s is always known to be a multiple of 4
    pub fn variable_base(point: &ExtendedPoint, s: &Scalar) -> ExtendedPoint {
        let mut result = ExtensibleCurvePoint::identity();

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

        result.to_extended()
    }

    // ------------------------------
    // CURVE POINT PROJECTION
    // ------------------------------

    /// Projects to affine x, y
    pub fn to_affine(&self) -> AffinePoint {
        let INV_Z = self.Z.invert();

        let mut X = self.X * INV_Z;
        X.strong_reduce();

        let mut Y = self.Y * INV_Z;
        Y.strong_reduce();

        AffinePoint { X, Y }
    }

    /// Projects to ExtendedPoint to ExtensiblePoint
    pub fn to_extensible(&self) -> ExtensibleCurvePoint {
        ExtensibleCurvePoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T1: self.T,
            T2: FieldElement::one(),
        }
    }

    /// Variant of Niels, where a Z coordinate is added for unmixed readdition
    /// ((y+x)/2, (y-x)/2, dxy, Z)
    pub fn to_projective_niels(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: self.Y + self.X,
            Y: self.Y - self.X,
            Z: self.Z,
            T: EDWARDS_D * self.X * self.Y,
        }
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

    /// Generates the curve
    pub fn generator() -> ExtendedPoint {
        ExtendedPoint {
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

// ------------------------------
// TESTS
// ------------------------------

#[test]
// 0 * G = 𝒪
pub fn test_g_times_zero_id() {
    let p = ExtendedPoint::tw_generator();
    let zero = Scalar::from(0_u64);
    let res = p * zero;
    let id = ExtendedPoint::id_point();

    assert!(res == id)
}

#[test]
// G * 1 = G
pub fn test_g_times_one_g() {
    let p = ExtendedPoint::tw_generator();
    let one = Scalar::from(1_u64);
    let res = p * one;
    let id = ExtendedPoint::tw_generator();

    assert!(res == id)
}

// G + (-G) = 𝒪
#[test]
fn test_g_plus_neg_g() {
    let g = ExtendedPoint::tw_generator();
    let neg_g = ExtendedPoint::tw_generator().negate();
    let id = g.add(&neg_g);

    assert_eq!(id, ExtendedPoint::id_point());
}

#[test]
// 2 * G = G + G
pub fn test_g_times_two_g_plus_g() {
    let g: ExtendedPoint = ExtendedPoint::tw_generator();
    let two = Scalar::from(2_u64);
    let res = g * two;
    let res2 = g.add(&g);

    assert!(res == res2)
}

#[test]
// 4 * G = 2 * (2 * G)
fn test_four_g() {
    let fourg = ExtendedPoint::variable_base(&ExtendedPoint::tw_generator(), &Scalar::from(4_u64));
    let two_times_twog = (ExtendedPoint::tw_generator().double()).double();

    assert!(fourg == two_times_twog)
}

#[test]
//4 * G != 𝒪
fn test_four_g_not_id() {
    let four_g = ExtendedPoint::tw_generator() * Scalar::from(4_u64);
    let id = ExtendedPoint::id_point();

    assert!(!(&four_g == &id))
}

#[test]
//r*G = 𝒪
fn r_times_g_id() {
    use crate::curve::field::scalar::R_448;
    let mut g = ExtendedPoint::generator();
    g = g * Scalar::from(U448::from_be_hex(R_448));
    let id = ExtendedPoint::id_point();

    assert!(!(&g == &id))
}

#[test]
// k * G = (k mod r) * G
fn k_g_equals_k_mod_r_times_g() {
    use crate::curve::field::scalar::R_448;
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_number: u64 = rng.gen();

    // k * G
    let k = U448::from(random_number);
    let g = ExtendedPoint::generator();

    // (k mod r) * G
    let gk = g * (Scalar::from(k));
    let r = U448::from_be_hex(R_448);
    let k_mod_r = k.const_rem(&r);
    let mut k_mod_r_timesg = ExtendedPoint::generator();
    k_mod_r_timesg = k_mod_r_timesg * (Scalar::from(k_mod_r.0));

    assert!(&gk == &k_mod_r_timesg)
}

#[test]
// (k + 1)*G = (k*G) + G
fn k_plus_one_g() {
    let mut rng = rand::thread_rng();
    let k = rand::Rng::gen::<u64>(&mut rng);

    let k1_g = ExtendedPoint::tw_generator() * Scalar::from::<u64>((k + 1).into());
    let k_g1 = (ExtendedPoint::tw_generator() * Scalar::from::<u64>(k.into()))
        .add(&ExtendedPoint::tw_generator());

    assert!(&k1_g == &k_g1)
}

#[test]
//(k + t)*G = (k*G) + (t*G)
fn k_t() {
    let mut rng = rand::thread_rng();
    let k: u32 = rand::Rng::gen::<u32>(&mut rng);
    let t: u32 = rand::Rng::gen::<u32>(&mut rng);

    //(k + t)*G
    let k_plus_t_G = ExtendedPoint::tw_generator() * (Scalar::from(k as u64 + t as u64));

    // (k*G) + (t*G)
    let kg_plus_tg = (ExtendedPoint::tw_generator() * Scalar::from(k as u64))
        .add(&(ExtendedPoint::tw_generator() * Scalar::from(t as u64)));

    assert!(k_plus_t_G == kg_plus_tg)
}

#[test]
//k*(t*G) = t*(k*G) = (k*t mod r)*G
fn test_ktg() {
    let mut rng = rand::thread_rng();
    let k: u32 = rand::Rng::gen::<u32>(&mut rng);
    let t: u32 = rand::Rng::gen::<u32>(&mut rng);

    //k*(t*G)
    let mut ktg = ExtendedPoint::tw_generator() * (Scalar::from(t as u64));
    ktg = ktg * (Scalar::from(k as u64));

    // t*(k*G)
    let mut tkg = ExtendedPoint::tw_generator() * (Scalar::from(k as u64));
    tkg = tkg * (Scalar::from(t as u64));

    // (k*t mod r)*G
    let ktmodr = Scalar::from(k as u64) * (Scalar::from(t as u64));
    let kt_modr_g = ExtendedPoint::tw_generator() * ktmodr;

    assert!(ktg == tkg);
    assert!(tkg == kt_modr_g);
    assert!(kt_modr_g == ktg);
}
