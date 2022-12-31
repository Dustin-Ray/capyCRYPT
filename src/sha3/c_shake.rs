pub mod shake_functions {
    use crate::sha3::sponge::sponge_mod::{sponge_squeeze, sponge_absorb};

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

}