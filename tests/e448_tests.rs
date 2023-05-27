#[cfg(test)]
mod e448_tests {
    use capycrypt::{
        curve::{CurvePoint, Generator, IdPoint},
        sha3::aux_functions::byte_utils::get_random_big,
    };

    use rand::{thread_rng, Rng};
    use rug::Integer as big;

    use capycrypt::curve::Curves;
    const SELECTED_CURVE: Curves = Curves::E448;

    #[test]
    // 0 * G = 𝒪
    fn test_zero_times_g() {
        let mut point = CurvePoint::generator(SELECTED_CURVE, false);
        let s = big::from(0);
        point = point * (s);
        let id_point = CurvePoint::id_point(SELECTED_CURVE);
        assert!(
            &id_point == &point,
            "points are not equal, check addition function"
        )
    }

    // G * 1 = G
    #[test]
    fn test_g_times_one() {
        let mut point = CurvePoint::generator(SELECTED_CURVE, false);
        let s = big::from(1);
        let g = CurvePoint::generator(SELECTED_CURVE, false);
        point = point * (s);
        // println!("point x: {}", point.x);
        // println!("point y: {}", point.y);
        assert!(
            &g == &point,
            "points are not equal, check mul and add functions"
        )
    }

    // G + (-G) = 𝒪
    #[test]
    fn test_g_plus_neg_g() {
        let g = CurvePoint::generator(SELECTED_CURVE, false);
        assert!(
            g.clone() + -g == CurvePoint::id_point(SELECTED_CURVE),
            "points are not equal, check mul and add functions"
        )
    }

    #[test]
    // 2 * G = G + G
    fn test_two_times_g() {
        let s = big::from(2);
        let two_g = CurvePoint::generator(SELECTED_CURVE, false) * (s);
        let mut sum_g = CurvePoint::generator(SELECTED_CURVE, false);
        sum_g = sum_g.clone() + sum_g.clone();
        assert!(
            &sum_g == &two_g,
            "points are not equal, check mul and add functions"
        )
    }

    #[test]
    // 4 * G = 2 * (2 * G)
    fn test_four_g() {
        let mut four_g = CurvePoint::generator(SELECTED_CURVE, false);
        four_g = four_g * (big::from(4));
        let two = big::from(2);
        let two_times_two_g =
            CurvePoint::generator(SELECTED_CURVE, false) * (two.clone()) * (two.clone());
        assert!(&four_g == &two_times_two_g)
    }

    #[test]
    //4 * G != 𝒪
    fn test_four_g_not_id() {
        let four_g = CurvePoint::generator(SELECTED_CURVE, false) * (big::from(4));
        let id = CurvePoint::id_point(SELECTED_CURVE);
        assert!(!(&four_g == &id))
    }

    #[test]
    //r*G = 𝒪
    fn r_times_g_id() {
        let g =
            CurvePoint::generator(SELECTED_CURVE, false) * (CurvePoint::id_point(SELECTED_CURVE).r);
        assert!(&g == &CurvePoint::id_point(SELECTED_CURVE))
    }

    #[test]
    // k*G = (k mod r)*G
    fn k_g_equals_k_mod_r_times_g() {
        let mut rng = thread_rng();
        let k_u128: u64 = rng.gen();
        let k = big::from(k_u128);
        let same_k = k.clone();
        let g = CurvePoint::generator(SELECTED_CURVE, false) * (k);
        let r = CurvePoint::generator(SELECTED_CURVE, false).r;
        let k_mod_r = same_k % r;
        let mut k_mod_r_timesg = CurvePoint::generator(SELECTED_CURVE, false);
        k_mod_r_timesg = k_mod_r_timesg * (k_mod_r);
        assert!(&g == &k_mod_r_timesg)
    }

    #[test]
    //(k + 1)*G = (k*G) + G
    fn k_plus_one_g() {
        let k = get_random_big(256);
        let k_2 = k.clone();
        let k1g = CurvePoint::generator(SELECTED_CURVE, false) * (k + 1);

        let mut kgg = CurvePoint::generator(SELECTED_CURVE, false) * (k_2);
        kgg = kgg + CurvePoint::generator(SELECTED_CURVE, false);
        assert!(&k1g == &kgg)
    }

    #[test]
    //(k + t)*G = (k*G) + (t*G)
    fn k_t() {
        let mut rng = thread_rng();
        let rnd: u64 = rng.gen();

        let k = big::from(rnd);
        let k_2 = k.clone();

        let t = big::from(rnd);
        let t_2 = t.clone();

        // (k + t)*G
        let r0 = CurvePoint::generator(SELECTED_CURVE, false) * (k + t);
        // (k*G)
        let mut r1 = CurvePoint::generator(SELECTED_CURVE, false) * (k_2);
        // (t*G)
        let r2 = CurvePoint::generator(SELECTED_CURVE, false) * (t_2);
        r1 = r1 + r2;
        assert!(&r1 == &r0)
    }

    #[test]
    //k*(t*P) = t*(k*G) = (k*t mod r)*G
    fn test_ktp() {
        let r = CurvePoint::generator(SELECTED_CURVE, false).r;
        let k = get_random_big(256);
        let k_2 = k.clone();
        let k_3 = k.clone();

        let t = get_random_big(256);
        let t_2 = t.clone();
        let t_3 = t.clone();

        let ktp = CurvePoint::generator(SELECTED_CURVE, false) * (t) * (k);
        let tkg = CurvePoint::generator(SELECTED_CURVE, false) * (k_2) * (t_2);
        let k_t_mod_r_g = CurvePoint::generator(SELECTED_CURVE, false) * ((k_3 * t_3) % r);

        assert!(&ktp == &tkg && &k_t_mod_r_g == &tkg && &k_t_mod_r_g == &ktp)
    }
}
