#![cfg(all(feature = "xxh32", unix, target_pointer_width = "64", feature = "large-input-test"))]

use xxhash_rust::xxh32::{xxh32, Xxh32};

#[test]
fn xxh32_large_updates_preserve_wrapping_length() {
    let four_gib = 1usize << 32;
    let mut payload = Vec::new();
    payload.resize(four_gib + 15, 0);
    let input = payload.as_slice();
    for (prefix_len, update_len) in [(0, four_gib), (15, four_gib), (15, four_gib - 1)] {
        let mut hasher = Xxh32::new(1);
        hasher.update(&input[..prefix_len]);
        hasher.update(&input[..update_len]);
        // Both updates contain only zero bytes, so their concatenation equals
        // the corresponding prefix of the mapping.
        let expected = unsafe {
            xxhash_c_sys::XXH32(input.as_ptr() as _, prefix_len + update_len, 1)
        };
        assert_eq!(hasher.digest(), expected, "prefix={prefix_len}, update={update_len}");
        assert_eq!(xxh32(&input[..prefix_len+update_len], 1), expected);
    }
}
