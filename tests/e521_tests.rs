#[cfg(test)]
mod e521_tests {
    use capyCRYPT::{curve::e521::e521_module::{
        get_e521_gen_point, 
        get_e521_id_point, 
        e521_equals, PointOps}, sha3::aux_functions::byte_utils::get_random_big};
    
    use rug::{Integer as big};
    use rand::{Rng, thread_rng};

    #[test]
    // 0 * G = 𝒪 
    fn test_zero_times_g() {
        let mut point  = get_e521_gen_point(false);
        let s = big::from(0);
        point = point.sec_mul(s);
        let id_point = get_e521_id_point();
        assert!(e521_equals(&id_point, &point), "points are not equal, check addition function")
    }

    // G * 1 = G
    #[test]
    fn test_g_times_one() {
        let mut point  = get_e521_gen_point(false);
        let s = big::from(1);
        let g = get_e521_gen_point(false);
        point = point.sec_mul(s);
        println!("{}", point.y);
        assert!(e521_equals(&g, &point), "points are not equal, check mul and add functions")
    }

    // G + (-G) = 𝒪
    #[test]
    fn test_g_plus_neg_g() {
        let mut g = get_e521_gen_point(false);
        let neg_g = g.negate_point();
        let id = get_e521_id_point();
        g = g.add(&neg_g);
        assert!(e521_equals(&g, &id), "points are not equal, check mul and add functions")
    }

    #[test]
    // 2 * G = G + G
    fn test_two_times_g() {
        let s = big::from(2);
        let two_g = get_e521_gen_point(false).sec_mul(s);
        let mut sum_g = get_e521_gen_point(false);
        sum_g = sum_g.add(&sum_g.clone());
        assert!(e521_equals(&sum_g, &two_g), "points are not equal, check mul and add functions")
    }

    #[test]
    // 4 * G = 2 * (2 * G)
    fn test_four_g() {
        let mut four_g = get_e521_gen_point(false);
        four_g = four_g.sec_mul(big::from(4));
        let two = big::from(2);
        let two_times_two_g = get_e521_gen_point(false).sec_mul(two.clone()).sec_mul(two.clone());
        assert!(e521_equals(&four_g, &two_times_two_g))
    }
    
    #[test]
    //4 * G != 𝒪 
    fn test_four_g_not_id() {
        let four_g = get_e521_gen_point(false).sec_mul(big::from(4));
        let id = get_e521_id_point();
        assert!(!e521_equals(&four_g, &id))
    }
    
    #[test]
    //r*G = 𝒪
    fn r_times_g_id() {
        let g = get_e521_gen_point(false).sec_mul(get_e521_id_point().r);
        assert!(e521_equals(&g, &get_e521_id_point()))
    }

    #[test]
    // k*G = (k mod r)*G
    fn k_g_equals_k_mod_r_times_g() {
        for _ in 0..5 {
            let mut rng = thread_rng();
            let k_u128: u64 = rng.gen();
            let k = big::from(k_u128);
            let same_k = k.clone();
            let g = get_e521_gen_point(false).sec_mul(k);
            let r = get_e521_gen_point(false).r;
            let k_mod_r = same_k % r;
            let mut k_mod_r_timesg = get_e521_gen_point(false);
            k_mod_r_timesg = k_mod_r_timesg.sec_mul(k_mod_r);
            assert!(e521_equals(&g, &k_mod_r_timesg))
        }
    }

    #[test]
    //(k + 1)*G = (k*G) + G
    fn k_plus_one_g() {
        for _ in 0..5 {
            
            let k = get_random_big(256);
            let k_2 = k.clone();
            let k1g = get_e521_gen_point(false).sec_mul(k + 1);

            let mut kgg = get_e521_gen_point(false).sec_mul(k_2);
            kgg = kgg.add(&get_e521_gen_point(false));
            assert!(e521_equals(&k1g, &kgg))
        }
    }

    #[test]
    //(k + t)*G = (k*G) + (t*G)
    fn k_t () {
        for _ in 0..5 {
            let mut rng = thread_rng();
            let rnd: u64 = rng.gen();
            
            let k = big::from(rnd);
            let k_2 = k.clone();

            let t = big::from(rnd);
            let t_2 = t.clone();

            // (k + t)*G
            let r0 = get_e521_gen_point(false).sec_mul(k+t);
            // (k*G)
            let mut r1 = get_e521_gen_point(false).sec_mul(k_2);
            // (t*G)
            let r2 = get_e521_gen_point(false).sec_mul(t_2);
            r1 = r1.add(&r2);
            assert!(e521_equals(&r1, &r0))
        }
    }

    #[test]
    //k*(t*P) = t*(k*G) = (k*t mod r)*G
    fn test_ktp() {

        for _ in 0..5 { 
            let r = get_e521_gen_point(false).r;
            let k = get_random_big(256);
            let k_2 = k.clone();
            let k_3 = k.clone();

            let t = get_random_big(256);
            let t_2 = t.clone();
            let t_3 = t.clone();

            let ktp = get_e521_gen_point(false).sec_mul(t).sec_mul(k);
            let tkg = get_e521_gen_point(false).sec_mul(k_2).sec_mul(t_2);
            let k_t_mod_r_g = get_e521_gen_point(false).sec_mul((k_3*t_3) % r);

            assert!(e521_equals(&ktp, &tkg) && e521_equals(&k_t_mod_r_g, &tkg) && e521_equals(&k_t_mod_r_g, &ktp))
        }
    }
}