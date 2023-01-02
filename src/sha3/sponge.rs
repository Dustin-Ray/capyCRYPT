pub mod sponge_function {

    use crate::sha3::keccakf::in_place::keccakf_1600;

    /** 
    Absorb rate amount of data into state and permute. Continue absorbing and permuting until
    No more data left in m. Pads to multiple of rate using multi-rate padding. 
        
        m: message to be absorbed
        capacity: security parameter which determines rate = bit_width - minus capacity
        return: a state consisting of 25 words of 64 bits each. */ 
    pub fn sponge_absorb(m: &mut Vec<u8>, capacity: usize) -> [u64; 25] {
        let r = (1600 - capacity) / 8;
        let rate_in_bytes = usize::try_from(r).unwrap(); //might not work on all architectures
        if m.len() % rate_in_bytes != 0 { pad_ten_one(m, rate_in_bytes); }
        let s = bytes_to_state(&m, rate_in_bytes);
        return s;
    }

    /** 
    Accepts state of 25 u64s and permutes, appending each iteration to output until
    Desired length is met.
        
        return: Vec<u8> consisting of absorbed and permuted states of length bit_length. */ 
    pub fn sponge_squeeze(s: &mut [u64; 25], bit_length: usize, rate: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new(); //FIPS 202 Algorithm 8 Step 8
        let block_size: usize = rate / 64;
        while out.len() * 8 < bit_length {
            out.extend_from_slice(&state_to_byte_array(&s[0..block_size]));
            keccakf_1600(s); //FIPS 202 Algorithm 8 Step 10
        }
        out.truncate(bit_length /8);
        out
    }

    /** Converts state of 25 u64s to array of bytes */
    fn state_to_byte_array(uint64s: &[u64]) -> Vec<u8> {
        let mut result = vec![];
        for v in uint64s {
            let mut b = u64_to_little_endian_bytes(v);
            result.append(&mut b);
        }
        result
    }

    /** Absorbs 200 bytes of message into constant memory size. */
    fn bytes_to_state(in_val: &[u8], rate_in_bytes: usize) -> [u64; 25] {
        let mut offset: u64 = 0;
        let mut s: [u64; 25] = [0; 25];

        for _ in 0..in_val.len() / rate_in_bytes {
            let mut state = [0u64; 25];
            for j in 0..((rate_in_bytes * 8) / 64) {
                state[j] = bytes_to_word(in_val, offset);
                offset += 8;
            }
            s = xor_states(&s, &state);
            keccakf_1600(&mut s);
        }
        return s;
    }

    /** Converts a u64 to le vec of bytes */ 
    pub fn u64_to_little_endian_bytes(n: &u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        for i in 0..8 {
            bytes[i] = (n >> (i * 8)) as u8;
        }
        bytes
    }
    
    /** xors 2 states of 26 u64s, assumes equal length. */
    fn xor_states(a: &[u64; 25], b: &[u64; 25]) -> [u64; 25] {
        let mut result: [u64; 25] = [0; 25];
        for i in 0..b.len() {
            result[i] ^= a[i] ^ b[i];
        }
        result
    }

    /** Converts bytes to u64 (aka a lane in keccak jargon) */
    fn bytes_to_word(in_val: &[u8], offset: u64) -> u64 {
        let mut lane: u64 = 0;
        for i in 0..8 {
            lane += (in_val[(i + offset) as usize] as u64 & 0xFF) << (8 * i);
        }
        lane
    }

    /** Multi-rate padding scheme defined in FIPS 202 5.1 */
    fn pad_ten_one(m: &mut Vec<u8>, rate_in_bytes: usize) {
        let q = rate_in_bytes - m.len() % rate_in_bytes;
        let mut padded = vec![0; q];
        padded[q - 1] = 0x80;
        m.extend_from_slice(&mut padded);
    }

}