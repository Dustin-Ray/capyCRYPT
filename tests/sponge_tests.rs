#[cfg(test)]
mod sponge_test {

    use cryptotool::sha3::sponge::sponge::{sponge_absorb, sponge_squeeze, bytes_to_hex_string};
    
    #[test]
    fn test_sponge_absorb() {

        let test_str = "test";
        let bytes = test_str.as_bytes();
        
        let res = sponge_squeeze(& mut sponge_absorb(bytes, 256), 512, 136);
        let byte_str = bytes_to_hex_string(&res);
        
        println!("{:?}", byte_str);
        assert!(true)

    }





}