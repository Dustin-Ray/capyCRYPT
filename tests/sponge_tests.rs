#[cfg(test)]
mod sponge_test {

    use cryptotool::sha3::{sponge::sponge_mod::{sponge_absorb, sponge_squeeze}, c_shake::shake_functions::compute_sha3_hash};
    use hex::ToHex;
    
    #[test]
    fn test_sponge() {

        let mut test_bytes = ("test").as_bytes().to_vec();
        
        let res = sponge_squeeze(& mut sponge_absorb(&mut test_bytes, 256), 512, 136);
        let s = res.encode_hex::<String>();
        
        let expected = "8ee1f95dfe959e1d5e8188df176516b25de2d1c5ebf8f3312a588fba9f0a23e7437379c2035a8208df6ab2b68a9327c7e42e13bdd7fc2222dd611f0f755d8808";
        assert!(s == expected)

    }


    #[test]
    fn test_shake() {

        let mut test_bytes = "".as_bytes().to_vec();
        let res = compute_sha3_hash(&mut test_bytes).encode_hex::<String>();
        let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
        assert!(res == expected);

        let mut test_bytes = "test".as_bytes().to_vec();
        let expected = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        let res = compute_sha3_hash(&mut test_bytes).encode_hex::<String>();
        assert!(res == expected);
    }


}