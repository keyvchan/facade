// implement of 32 bits fnv 1a hash

pub(crate) fn fnv(data: &[u8]) -> u32 {
    let mut hash = 2166136261;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}
