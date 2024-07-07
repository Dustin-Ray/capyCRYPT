use super::constants::{BitLength, Rate};
use crate::sha3::keccakf::keccakf_1600;

// Absorbs rate amount of data into state and permutes. Continue absorbing and permuting until
// no more data left in m. Pads to multiple of rate using multi-rate padding.
//
// * m: message to be absorbed
// * capacity: security parameter which determines rate = bit_width - capacity
// * return: a state consisting of 25 words of 64 bits each.
pub(crate) fn sponge_absorb<C: BitLength>(m: &mut Vec<u8>, capacity: C) -> [u64; 25] {
    let c = capacity.bit_length();
    let r = (1600 - c) / 8;
    if (m.len() % r) != 0 {
        pad_ten_one(m, r);
    }
    bytes_to_state(m, r)
}

// Finalizes a state.
//
// * s: the state to finalize
// * bit_length: requested output length in bits
// * rate: security parameter
// * return: digest of permuted states of length `bit_length`.
pub(crate) fn sponge_squeeze(s: &mut [u64; 25], bit_length: usize, rate: Rate) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new(); //FIPS 202 Algorithm 8 Step 8
    let block_size: usize = rate.value() / 64;
    while out.len() * 8 < bit_length {
        out.append(&mut state_to_byte_array(&s[0..block_size]));
        keccakf_1600(s); //FIPS 202 Algorithm 8 Step 10
    }
    out.truncate(bit_length / 8);
    out
}

// Converts state of 25 u64s to array of bytes.
fn state_to_byte_array(uint64s: &[u64]) -> Vec<u8> {
    let mut result = vec![];
    for v in uint64s {
        let mut b = u64_to_little_endian_bytes(v);
        result.append(&mut b);
    }
    result
}

// Absorbs 200 bytes of message into fixed memory size.
fn bytes_to_state(in_val: &mut [u8], rate_in_bytes: usize) -> [u64; 25] {
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

// Converts bytes to u64 (aka word/lane)
fn bytes_to_word(in_val: &[u8], offset: usize) -> u64 {
    let mut lane: u64 = 0;
    for i in 0..8 {
        lane += (in_val[i + offset] as u64 & 0xFF) << (8 * i);
    }
    lane
}

// Shifts u64 into `Vec<u8>`
pub(crate) fn u64_to_little_endian_bytes(n: &u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 8];
    for (i, el) in bytes.iter_mut().enumerate().take(8) {
        *el = (n >> (i * 8)) as u8;
    }
    bytes
}

// xors 2 states of 26 u64s in place, assumes equal length.
fn xor_states(a: &mut [u64; 25], b: &[u64; 25]) {
    for i in 0..b.len() {
        a[i] ^= b[i];
    }
}

// # NIST FIPS 202 5.1
// Multi-rate padding scheme
fn pad_ten_one(m: &mut Vec<u8>, rate_in_bytes: usize) {
    let q = rate_in_bytes - m.len() % rate_in_bytes;

    let mut padded = vec![0; q];
    padded[q - 1] = 0x80;
    m.append(&mut padded);
}

/// Test cases for cSHAKE and KMAC functionality. All values labeled
/// "exptected" in cshake and kmac tests are official test vectors supplied by NIST.
#[cfg(test)]
mod sponge_tests {
    use crate::sha3::{
        aux_functions::nist_800_185::{byte_pad, left_encode, right_encode},
        constants::NIST_DATA_SPONGE_INIT,
    };

    #[test]
    fn test_bytepad() {
        let mut val = "test".as_bytes().to_vec();
        let val_len = val.len() as u32;
        let expected = [1, 4, 116, 101, 115, 116, 0, 0];
        assert_eq!(byte_pad(&mut val, val_len), expected);

        let expected = [
            1, 200, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
            44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
            66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
            88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
            125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
            142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158,
            159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
            176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
            193, 194, 195, 196, 197, 198, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];

        let val: [u8; 200] = NIST_DATA_SPONGE_INIT;
        let val_len = val.len() as u32;
        assert_eq!(byte_pad(&mut val.to_vec(), val_len), expected);
    }

    #[test]
    fn test_right_encode() {
        let val = 0;
        let expected = [0, 1];
        assert_eq!(right_encode(val), expected);

        let val = 0xFFFFFFFFFFFFFF;
        let expected = [8, 255, 255, 255, 255, 255, 255, 255];
        assert_eq!(right_encode(val), expected);

        let val = 10000000000;
        let expected = [6, 0, 0, 2, 84, 11];
        assert_eq!(right_encode(val), expected);

        let val = 10000000000000000000;
        let expected = [8, 199, 35, 4, 137, 232, 0, 0];
        assert_eq!(right_encode(val), expected);

        let val: [u8; 200] = NIST_DATA_SPONGE_INIT;
        let val_len = val.len();
        let expected = [2, 0];

        let res = right_encode(val_len as u64);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_left_encode() {
        let val = 0;
        let expected = [1, 0];
        assert_eq!(left_encode(val), expected);

        let val = 0xFFFFFFFFFFFFFF;
        let expected = [7, 255, 255, 255, 255, 255, 255, 255];
        assert_eq!(left_encode(val), expected);

        let val = 10000000000;
        let expected = [5, 2, 84, 11, 228, 0];
        assert_eq!(left_encode(val), expected);

        let val = 10000000000000000000;
        let expected = [8, 138, 199, 35, 4, 137, 232, 0, 0];
        assert_eq!(left_encode(val), expected);

        let val: [u8; 200] = NIST_DATA_SPONGE_INIT;
        let val_len = val.len();
        let expected = [1, 200];

        let res = left_encode(val_len as u64);
        assert_eq!(res, expected);
    }
}
