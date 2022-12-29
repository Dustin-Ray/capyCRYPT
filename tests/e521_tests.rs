#[cfg(test)]
mod e521_tests {
    
    use cryptotool::curve::e521::e521::{get_e521_gen_point, get_e521_id_point, sec_mul, negate_point, add_points, e521_equals};
    use num::Integer;
    use num_bigint::{BigInt};
    use rand::{Rng, thread_rng};
    #[test]
    // 0 * G = 𝒪 
    fn test_zero_times_g() {
        let point  = get_e521_gen_point(false);
        let s = BigInt::from(0);
        let result = sec_mul(s, point);
        let id_point = get_e521_id_point();
        assert!(e521_equals(&id_point, &result), "points are not equal, check addition function")
        
    }

    // G * 1 = G
    #[test]
    fn test_g_times_one() {
        
        let point  = get_e521_gen_point(false);
        let s = BigInt::from(1);
        let g = get_e521_gen_point(false);
        let result = sec_mul(s, point);
        
        assert!(e521_equals(&g, &result), "points are not equal, check mul and add functions")
    }

    // G + (-G) = 1
    #[test]
    fn test_g_plus_neg_g() {

        let g = get_e521_gen_point(false);
        let neg_g = negate_point(&g);

        let id = get_e521_id_point();
        let sum = add_points(&g, &neg_g);
        assert!(e521_equals(&sum, &id), "points are not equal, check mul and add functions")
        
    }

    #[test]
    // 2 * G = G + G
    fn test_two_times_g() {

        let g = get_e521_gen_point(false);
        let s = BigInt::from(2);

        let product = sec_mul(s, g);

        let g = get_e521_gen_point(false);
        let sum = add_points(&g, &g);

        assert!(e521_equals(&sum, &product), "points are not equal, check mul and add functions")
    }

    #[test]
    // 4 * G = 2 * (2 * G)
    fn test_four_g() {

        let four_g = sec_mul(BigInt::from(4), get_e521_gen_point(false));
        let two_times_two_g = sec_mul(BigInt::from(2), sec_mul(BigInt::from(2), get_e521_gen_point(false)));
        
        assert!(e521_equals(&four_g, &two_times_two_g))
    }

    #[test]
    //4 * G != 𝒪 
    fn test_four_g_not_id() {
        let four_g = sec_mul(BigInt::from(4), get_e521_gen_point(false));
        let id = get_e521_id_point();

        assert!(!e521_equals(&four_g, &id))

    }

    #[test]
    fn r_times_g_id() {
        let g = get_e521_gen_point(false);
        let result = sec_mul(g.r, get_e521_gen_point(false));
        assert!(e521_equals(&result, &get_e521_id_point()))
    }

    #[test]
    // k*G = (k mod r)*G
    fn k_g_equals_k_mod_r_times_g() {
        
        for _ in 0..20 {
            let mut rng = thread_rng();
            let k_u128: u64 = rng.gen();
            let k = BigInt::from(k_u128);
            let same_k = k.clone();

            let g = get_e521_gen_point(false);
            let r = get_e521_gen_point(false).r;
            let k_g = sec_mul(k, g);

            let k_mod_r = same_k.mod_floor(&r);
            let k_mod_r_timesg = sec_mul(k_mod_r, get_e521_gen_point(false));
            assert!(e521_equals(&k_g, &k_mod_r_timesg))
        }
    }
    #[test]
    //(k + 1)*G = (k*G) + G
    fn k_plus_one_g() {

        for _ in 0..20 {
            let mut rng = thread_rng();
            let k_u128: u64 = rng.gen();
            let k = BigInt::from(k_u128);
            let k_plus_one = k.clone()+1;

            let k_plus_one_g = sec_mul(k_plus_one, get_e521_gen_point(false));

            let k_g_plus_g = sec_mul(k, get_e521_gen_point(false));
            let k_g_plus_g = add_points(&k_g_plus_g, &get_e521_gen_point(false));

            assert!(e521_equals(&k_plus_one_g, &k_g_plus_g))
        }
    }
    #[test]
    //(k + t)*G = (k*G) + (t*G)
    fn k_t () {
        
        for _ in 0..20 {
            let mut rng = thread_rng();
            
            let rnd: u64 = rng.gen();
            let k = BigInt::from(rnd);
            let k_2 = k.clone();

            let t = BigInt::from(rnd);
            let t_2 = t.clone();

            let r0 = sec_mul(k+t, get_e521_gen_point(false));
            
            let r1 = sec_mul(k_2, get_e521_gen_point(false));
            let r2 = sec_mul(t_2, get_e521_gen_point(false));
            let r3 = add_points(&r1,&r2);

            assert!(e521_equals(&r0, &r3))
        }
    }

    #[test]
    //k*(t*P) = t*(k*G) = (k*t mod r)*G
    fn test_ktp() {

        for _ in 0..20 {
            let r = get_e521_gen_point(false);
            let r = r.r;
            let mut rng = thread_rng();
                
            let rnd: u64 = rng.gen();
            let k = BigInt::from(rnd);
            let k_2 = k.clone();
            let k_3 = k.clone();

            let t = BigInt::from(rnd);
            let t_2 = t.clone();
            let t_3 = t.clone();

            let ktp = sec_mul(k, sec_mul(t, get_e521_gen_point(false)));
            let tkg = sec_mul(t_2, sec_mul(k_2, get_e521_gen_point(false)));

            let k_t_mod_r_g = sec_mul((k_3*t_3).mod_floor(&r), get_e521_gen_point(false));

            assert!(e521_equals(&ktp, &tkg) && e521_equals(&k_t_mod_r_g, &tkg) && e521_equals(&k_t_mod_r_g, &ktp))
        }

    }
}