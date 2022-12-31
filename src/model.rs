pub mod shake_functions {
    use crate::sha3::sponge::sponge_function::{sponge_squeeze, sponge_absorb};
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};

    /** SHA3-Keccak ref NIST FIPS 202.
    N: pointer to message to be hashed.
    d: requested output length */
    fn shake(n: &mut Vec<u8>, d: usize) -> Vec<u8> {

        let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
        if bytes_to_pad == 1 { n.extend_from_slice(&[0x86]);} //delim suffix
        else { n.extend_from_slice(&[0x06]);} //delim suffix
        return  sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600-(2*d));
    }

    /**Computes SHA3-512 hash of data */
    pub fn compute_sha3_hash(data: &mut Vec<u8>) -> Vec<u8> {
        shake(data, 512)
    }

    /**
    FIPS 202 Section 3 cSHAKE function returns customizable and
    domain seperated length L SHA3XOF hash of input string.

        X: input message in bytes
        L: requested output length
        N: optional function name string
        S: option customization string
        return: SHA3XOF hash of length L of input message X
    */
    pub fn cshake(x: &mut Vec<u8>, l: u64, n: &str, s: &str) -> Vec<u8> {
        if n == "" && s == "" { return shake(x, l as usize) }
        let mut encoded_n = encode_string(&mut n.as_bytes().to_vec());
        let mut encoded_s = encode_string(&mut s.as_bytes().to_vec());
        encoded_n.extend_from_slice(& mut encoded_s);
        let mut out = byte_pad(&mut encoded_n, 136);
        out.append(x);
        out.push(0x04);
        return sponge_squeeze(&mut sponge_absorb(&mut out, 512), l as usize, 1600-512);
    }

    /**
    Generates keyed hash for given input as specified in NIST SP 800-185 section 4.
        K: key
        X: byte-oriented message
        L: requested bit length
        S: customization string
        return: KMACXOF256 of X under K
    */
    pub fn kmac_xof_256(k: &mut Vec<u8>, x: &mut Vec<u8>, l: u64, s: &str) -> Vec<u8>{
        let mut encode_s = encode_string(k);
        let mut bp = byte_pad(&mut encode_s, 136);
        bp.append(x);
        let mut right_enc = right_encode(0);
        bp.append(&mut right_enc);
        let res = cshake(&mut bp, l, "KMAC", s);
        res
    }

}