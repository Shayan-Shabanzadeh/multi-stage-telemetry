pub const COUNTER_PER_BUCKET: usize = 8;
pub const MAX_VALID_COUNTER: usize = 7;
pub const ALIGNMENT: usize = 64;
pub const COUNTER_PER_WORD: usize = 8;
pub const BIT_TO_DETERMINE_COUNTER: usize = 3;
pub const K_HASH_WORD: usize = 1;
pub const KEY_LENGTH_4: usize = 4;
pub const KEY_LENGTH_13: usize = 13;
pub const CONSTANT_NUMBER: u32 = 2654435761;

pub fn calculate_bucket_pos(fp: u32) -> usize {
    ((fp as u64 * CONSTANT_NUMBER as u64) >> 15) as usize
}

pub fn get_counter_val(val: u32) -> u32 {
    val & 0x7FFFFFFF
}

pub fn judge_if_swap(min_val: u32, guard_val: u32) -> bool {
    guard_val > (min_val << 3)
}

pub fn update_guard_val(guard_val: u32) -> u32 {
    guard_val + 1
}

pub fn highest_bit_is_1(val: u32) -> bool {
    val & 0x80000000 != 0
}