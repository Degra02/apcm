
pub fn right_pad_0s(bytes: &[u8], length: usize) -> Vec<u8> {
    let mut padded = vec![0_u8; length];
    padded[..bytes.len()].copy_from_slice(bytes);
    padded
}

pub fn left_pad_0s(bytes: &[u8], length: usize) -> Vec<u8> {
    if length <= bytes.len() {
        return bytes.to_vec();
    }
    let init_cap = length - bytes.len();
    //println!("init_cap: {}, length: {}, bytes.len(): {}", init_cap, length, bytes.len());
    let mut padded = vec![0_u8; init_cap];
    padded.extend(bytes.iter());
    padded
}

pub fn to_k_bytes_be(x: &num_bigint::BigUint, k: usize) -> Vec<u8> {
    let mut x_bytes = x.to_bytes_be();
    while x_bytes.len() < k {
        x_bytes.insert(0, 0u8);
    }
    x_bytes
}
