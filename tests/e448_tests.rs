#![allow(non_snake_case)]
// ------------------------------
// TESTS
// ------------------------------
use capycrypt::curve::{extended_edwards::ExtendedPoint, field::scalar::{Scalar, R_448}};
use crypto_bigint::U448;

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
    let four_g = ExtendedPoint::tw_generator() * Scalar::from(4_u64);
    let two_times_two_g = (ExtendedPoint::tw_generator().double()).double();

    assert!(four_g == two_times_two_g)
}

#[test]
//4 * G != 𝒪
fn test_four_g_not_id() {
    let four_g = ExtendedPoint::generator() * Scalar::from(4_u64);
    let tw_four_g = ExtendedPoint::generator() * Scalar::from(4_u64);
    let id = ExtendedPoint::id_point();

    assert!(!(&four_g == &id));
    assert!(!(&tw_four_g == &id))
}

#[test]
//r*G = 𝒪
fn r_times_g_id() {
    let mut g = ExtendedPoint::generator();
    g = g * Scalar::from(U448::from_be_hex(R_448));
    let id = ExtendedPoint::id_point();

    assert!(!(&g == &id))
}

#[test]
// k * G = (k mod r) * G
fn k_g_equals_k_mod_r_times_g() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_number: u64 = rng.gen();

    // k * G
    let k = U448::from(random_number);
    let g = ExtendedPoint::tw_generator();

    // (k mod r) * G
    let gk = g * (Scalar::from(k));
    let r = U448::from_be_hex(R_448);
    let k_mod_r = k.const_rem(&r);
    let mut k_mod_r_timesg = ExtendedPoint::tw_generator();
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
