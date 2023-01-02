pub mod shake_functions {
    use crate::sha3::sponge::sponge_function::{sponge_squeeze, sponge_absorb};
    use crate::sha3::aux_functions::nist_800_185::{byte_pad, encode_string, right_encode};
    use crate::sha3::aux_functions::byte_utils::{xor_bytes, get_random_bytes};
    
    use crate::SymmetricCryptogram;

    /** 
    SHA3-Keccak ref NIST FIPS 202.
    
        N: pointer to message to be hashed.
        D: requested output length */
    fn shake(n: &mut Vec<u8>, d: usize) -> Vec<u8> {

        let bytes_to_pad = 136 - n.len() % 136; // SHA3-256 r = 1088 / 8 = 136
        if bytes_to_pad == 1 { n.extend_from_slice(&[0x86]);} //delim suffix
        else { n.extend_from_slice(&[0x06]);} //delim suffix
        return  sponge_squeeze(&mut sponge_absorb(n, 2 * d), d, 1600-(2*d));
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
        return: kmac_xof_256 of X under K
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

    /**Computes SHA3-512 hash of data */
    pub fn compute_sha3_hash(data: &mut Vec<u8>) -> Vec<u8> {
        shake(data, 512)
    }

    /**
    Computes an authentication tag t of a byte array m under passphrase pw

        pw: symmetric encryption key, can be blank
        message: message to encrypt
        S: customization string
        return: t <- kmac_xof_256(pw, m, 512, “T”)
    */
    pub fn compute_tagged_hash(pw: &mut Vec<u8>, message: &mut Vec<u8>, s: &mut str) -> Vec<u8> {
        kmac_xof_256(pw, message, 512, s)
    }

    /**
    Encrypts a byte array m symmetrically under passphrase pw:
	    SECURITY NOTE: ciphertext length == plaintext length
        
        pw: symmetric encryption key, can be blank
        message: message to encrypt

        z <- Random(512)
        (ke || ka) <- kmac_xof_256(z || pw, “”, 1024, “S”)
        c <- kmac_xof_256(ke, “”, |m|, “SKE”) xor m
        t <- kmac_xof_256(ka, m, 512, “SKA”)
        return: symmetric cryptogram: (z, c, t)
    */
    pub fn encrypt_with_pw(pw: &mut Vec<u8>, msg: &mut Vec<u8>) -> SymmetricCryptogram{

        let z = get_random_bytes();
        let mut temp_ke_ka = z.clone();
        temp_ke_ka.append(pw);
        let ke_ka = kmac_xof_256(&mut temp_ke_ka, &mut vec![], 1024, "S");
        let mut c = kmac_xof_256(&mut ke_ka[0..ke_ka.len() / 2].to_vec(), &mut vec![], (msg.len() * 8) as u64, "SKE");
        xor_bytes(&mut c, &msg);
        let t = kmac_xof_256(&mut ke_ka[ke_ka.len() / 2..ke_ka.len()].to_vec(), msg, 512, "SKA");
        let cg = SymmetricCryptogram{z,c,t};
        cg
    }

    /**
    Decrypts a symmetric cryptogram (z, c, t) under passphrase pw.
    Assumes that decryption is well-formed. Parsing and error checking
    should occur in controller which handles user input.

        msg: cryptogram to decrypt, assumes valid format.
        pw: decryption password, can be blank

        (ke || ka) <- kmac_xof_256(z || pw, “”, 1024, “S”)
        m <- kmac_xof_256(ke, “”, |c|, “SKE”) xor c
        t’ <- kmac_xof_256(ka, m, 512, “SKA”)
        return: m, if and only if t` = t
    */
    pub fn decrypt_with_pw(pw: &mut Vec<u8>, msg: &mut SymmetricCryptogram) -> bool{

        msg.z.append(pw);
        let ke_ka = kmac_xof_256(&mut msg.z, &mut vec![], 1024, "S");
        let ke = &mut ke_ka[0..ke_ka.len() / 2].to_vec();
        let ka = &mut ke_ka[ke_ka.len() / 2..ke_ka.len()].to_vec();
        let mut c = kmac_xof_256(ke, &mut vec![], (msg.c.len() * 8) as u64, "SKE");
        xor_bytes(&mut c, &msg.c);
        let t_p = kmac_xof_256(ka, &mut c, 512, "SKA");
        msg.c = c;
        if t_p == msg.t { return true; } //timing issue here?
        else { return false; }
    }

}