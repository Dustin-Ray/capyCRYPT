#[cfg(test)]
pub mod model_test {
    

    use std::{time::Instant, str::FromStr};
    use cryptotool::{
        model::shake_functions::{encrypt_with_pw, decrypt_with_pw, gen_keypair, encrypt_with_key, decrypt_with_key}, 
        curve::e521::e521_module::{get_e521_gen_point, PointOps, get_e521_point}, KeyObj, sha3::aux_functions::byte_utils::bytes_to_big};
    use cryptotool::sha3::aux_functions::byte_utils::get_random_bytes;
    use rug::{Integer as big};


    #[test]
    pub fn test_sym_enc<'a>() {
        // the next thing to try is to return the original message
        //from the call chain

        let mut total = 0.0;
        for _ in 0..20 {
            let now = Instant::now();
            let pw = get_random_bytes(16);
            let mut message = get_random_bytes(5242880);
            let mut cg2 = encrypt_with_pw(&mut pw.clone(), &mut message);
            let res = decrypt_with_pw(&mut pw.clone(), &mut cg2);
            let elapsed = now.elapsed();
            let sec = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0);
            total += sec;
            assert!(res);
        }
        println!("Code took: {} seconds", total / 20.0);
    }

    #[test]
    fn test_key_gen() {

        let mut pw = get_random_bytes(16); 
            
        let mut pw2 = get_random_bytes(16); 

        let owner = "test key".to_string();
        let message = get_random_bytes(5242880);
        let key_obj = gen_keypair(&mut pw.clone(), owner);
        let x = key_obj.pub_key_x.as_bytes().to_vec();
        let y = key_obj.pub_key_y.as_bytes().to_vec();

        let mut pub_key = get_e521_point(
            bytes_to_big(x),
            bytes_to_big(y));
        
        let enc = encrypt_with_key(&mut pub_key, &message);
        // let res = decrypt_with_key(&mut pw.clone(), &enc);
        // assert!(res);




    }
}