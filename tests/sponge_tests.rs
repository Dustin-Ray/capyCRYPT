#[cfg(test)]
mod sponge_test {

    use cryptotool::sha3::sponge::sponge_mod::{sponge_absorb, sponge_squeeze};
    use hex::ToHex;
    
    #[test]
    fn test_sponge_absorb() {

        let test_str = "test";
        let bytes = test_str.as_bytes();
        
        let res = sponge_squeeze(& mut sponge_absorb(bytes, 256), 512, 136);
        let s = res.encode_hex::<String>();
        
        println!("{:?}", s);
        assert!(true)

    }





}