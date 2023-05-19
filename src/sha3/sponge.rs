pub mod sponge_function {
    use crate::sha3::keccakf::in_place::keccakf_1600;

    /// Absorbs rate amount of data into state and permute. Continue absorbing and permuting until
    /// No more data left in m. Pads to multiple of rate using multi-rate padding.
    ///
    /// * `m`: message to be absorbed
    /// * `capacity`: security parameter which determines rate = ```bit_width``` - ```capacity```
    /// * `return`: a ```state``` consisting of 25 words of 64 bits each.
    pub fn sponge_absorb(m: &mut Vec<u8>, capacity: usize) -> [u64; 25] {
        let r = (1600 - capacity) / 8;
        if m.len() % r != 0 {
            pad_ten_one(m, r);
        }
        bytes_to_state(m, r)
    }

    /// Accepts state of 25 ```u64```s and permutes, appending each iteration to output until
    /// desired length is met.
    ///
    /// * `return`: Vec<u8> consisting of absorbed and permuted states of length bit_length.
    pub fn sponge_squeeze(s: &mut [u64; 25], bit_length: usize, rate: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new(); //FIPS 202 Algorithm 8 Step 8
        let block_size: usize = rate / 64;
        while out.len() * 8 < bit_length {
            out.extend_from_slice(&state_to_byte_array(&s[0..block_size]));
            keccakf_1600(s); //FIPS 202 Algorithm 8 Step 10
        }
        out.truncate(bit_length / 8);
        out
    }

    /// Converts state of 25 u64s to array of bytes
    fn state_to_byte_array(uint64s: &[u64]) -> Vec<u8> {
        let mut result = vec![];
        for v in uint64s {
            let mut b = u64_to_little_endian_bytes(v);
            result.append(&mut b);
        }
        result
    }

    /// Absorbs 200 bytes of message into constant memory size.
    fn bytes_to_state(in_val: &Vec<u8>, rate_in_bytes: usize) -> [u64; 25] {
        let mut offset: usize = 0;
        let mut s: [u64; 25] = [0; 25];
        for _ in 0..in_val.len() / rate_in_bytes {
            let mut state = [0u64; 25];
            for el in state.iter_mut().take((rate_in_bytes * 8) / 64) {
                *el = bytes_to_word(in_val, offset);
                offset += 8;
            }
            xor_states(&mut s, &state);
            keccakf_1600(&mut s);
        }
        s
    }

    /// Converts bytes to u64 (aka a lane in keccak jargon)
    fn bytes_to_word(in_val: &[u8], offset: usize) -> u64 {
        let mut lane: u64 = 0;
        for i in 0..8 {
            lane += (in_val[i + offset] as u64 & 0xFF) << (8 * i);
        }
        lane
    }

    /// Shifts u64 into Vec<u8>
    pub fn u64_to_little_endian_bytes(n: &u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        for (i, el) in bytes.iter_mut().enumerate().take(8) {
            *el = (n >> (i * 8)) as u8;
        }
        bytes
    }

    //// xors 2 states of 26 u64s in place, assumes equal length.
    fn xor_states(a: &mut [u64; 25], b: &[u64; 25]) {
        for i in 0..b.len() {
            a[i] ^= b[i];
        }
    }

    /// # NIST FIPS 202 5.1
    /// Multi-rate padding scheme
    fn pad_ten_one(m: &mut Vec<u8>, rate_in_bytes: usize) {
        let q = rate_in_bytes - m.len() % rate_in_bytes;
        let mut padded = vec![0; q];
        padded[q - 1] = 0x80;
        m.extend_from_slice(&padded);
    }
}
