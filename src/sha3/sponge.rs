pub mod sponge {

    use crate::sha3::keccakf::in_place::keccakf_1600;

    pub fn sponge_absorb(m: &[u8], capacity: i32) -> [u64; 25] {
        let r = (1600 - capacity) / 8;
        let rate_in_bytes = usize::try_from(r).unwrap(); //might not work on all architectures
        let mut p = m.to_vec();
        
        if m.len() % rate_in_bytes != 0 {
            p = pad_ten_one(&m, rate_in_bytes);
        }
        
        let state_array = bytes_to_states(&p, rate_in_bytes);
        let mut s: [u64; 25] = [0; 25];
        
        for st in state_array {
            s = xor_states(&s, &st);
            keccakf_1600(&mut s);
        }
        return s;
    }


    pub fn sponge_squeeze(s: &mut [u64; 25], bit_length: usize, rate: usize) -> Vec<u8> {
        let mut out: Vec<u64> = Vec::new(); //FIPS 202 Algorithm 8 Step 8
        let block_size: usize = rate / 64;
    
        while out.len() * 64 < bit_length {
            out.extend_from_slice(&s[0..block_size]);
            keccakf_1600(s); //FIPS 202 Algorithm 8 Step 10
        }
    
        let byte_array = state_to_byte_array(&out);
        
        byte_array[..bit_length/8].to_vec() //FIPS 202 3.1
    }

    fn state_to_byte_array(uint64s: &[u64]) -> Vec<u8> {
        
        let mut result = vec![];
        for v in uint64s {
            let mut b = u64_to_little_endian_bytes(v);
            result.append(&mut b);
        }
        result
    }

    pub fn u64_to_little_endian_bytes(n: &u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        for i in 0..8 {
            bytes[i] = (n >> (i * 8)) as u8;
        }
        bytes
    }
    

    fn xor_states(a: &[u64; 25], b: &[u64; 25]) -> [u64; 25] {
        let mut result: [u64; 25] = [0; 25];
        for i in 0..b.len() {
            result[i] ^= a[i] ^ b[i];
        }
        result
    }

    fn bytes_to_states(in_val: &[u8], rate_in_bytes: usize) -> Vec<[u64; 25]> {
        let mut state_array = vec![[0u64; 25]; in_val.len() / rate_in_bytes];
        let mut offset: u64 = 0;
        for i in 0..state_array.len() {
            let mut state = [0u64; 25];
            for j in 0..((rate_in_bytes * 8) / 64) {
                state[j] = bytes_to_lane(in_val, offset);
                offset += 8;
            }
            state_array[i] = state;
        }
        return state_array;
    }

    fn bytes_to_lane(in_val: &[u8], offset: u64) -> u64 {
        let mut lane: u64 = 0;
        for i in 0..8 {
            lane += (in_val[(i + offset) as usize] as u64 & 0xFF) << (8 * i);
        }
        lane
    }

    fn pad_ten_one(x: &[u8], rate_in_bytes: usize) -> Vec<u8> {
        let q = rate_in_bytes - x.len() % rate_in_bytes;
        let mut padded = vec![0; x.len() + q];
        padded[..x.len()].copy_from_slice(x);
        padded[x.len() + q - 1] = 0x80;
        padded
    }


    pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
        let mut hex_string = String::new();
        for byte in bytes {
            hex_string.push_str(&format!("{:x}", byte));
        }
        hex_string
    }

    pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut iter = hex.chars().peekable();
        while let Some(c) = iter.next() {
            let n1 = c.to_digit(16).unwrap();
            let n2 = iter.peek().map_or(0, |c| c.to_digit(16).unwrap());
            bytes.push((n1 << 4 | n2) as u8);
        }
        bytes
    }

}