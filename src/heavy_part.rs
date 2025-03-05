use crate::param::*;
use std::mem::size_of;

#[repr(align(64))]
pub struct Bucket {
    key: [u32; COUNTER_PER_BUCKET],
    val: [u32; COUNTER_PER_BUCKET],
}

pub struct HeavyPart<const BUCKET_NUM: usize> {
    buckets: [Bucket; BUCKET_NUM],
}

impl<const BUCKET_NUM: usize> HeavyPart<BUCKET_NUM> {
    pub fn new() -> Self {
        Self {
            buckets: unsafe { std::mem::zeroed() },
        }
    }

    pub fn clear(&mut self) {
        for bucket in &mut self.buckets {
            bucket.key.fill(0);
            bucket.val.fill(0);
        }
    }

    pub fn insert(&mut self, key: &[u8], swap_key: &mut [u8], swap_val: &mut u32, f: u32) -> i32 {
        let fp = u32::from_ne_bytes(key.try_into().unwrap());
        let pos = calculate_bucket_pos(fp) % BUCKET_NUM;

        let item = std::arch::x86_64::_mm256_set1_epi32(fp as i32);
        let keys_p = unsafe { &*(self.buckets[pos].key.as_ptr() as *const __m256i) };
        let matched = unsafe { std::arch::x86_64::_mm256_cmpeq_epi32(item, *keys_p) };
        let matched_mask = unsafe { std::arch::x86_64::_mm256_movemask_ps(std::mem::transmute(matched)) };

        if matched_mask != 0 {
            let matched_index = matched_mask.trailing_zeros() as usize;
            self.buckets[pos].val[matched_index] += f;
            return 0;
        }

        let mask_base = 0x7FFFFFFF;
        let counters = unsafe { &*(self.buckets[pos].val.as_ptr() as *const __m256i) };
        let masks = unsafe { std::arch::x86_64::_mm256_set1_epi32(mask_base as i32) };
        let results = unsafe { std::arch::x86_64::_mm256_and_ps(std::mem::transmute(*counters), std::mem::transmute(masks)) };
        let mask2 = unsafe { std::arch::x86_64::_mm256_set_epi32(mask_base as i32, 0, 0, 0, 0, 0, 0, 0) };
        let results = unsafe { std::arch::x86_64::_mm256_or_ps(results, std::mem::transmute(mask2)) };

        let low_part = unsafe { std::arch::x86_64::_mm256_extractf128_ps(results, 0) };
        let high_part = unsafe { std::arch::x86_64::_mm256_extractf128_ps(results, 1) };
        let x = unsafe { std::arch::x86_64::_mm_min_epi32(std::mem::transmute(low_part), std::mem::transmute(high_part)) };
        let min1 = unsafe { std::arch::x86_64::_mm_shuffle_epi32(x, std::arch::x86_64::_MM_SHUFFLE(0, 0, 3, 2)) };
        let min2 = unsafe { std::arch::x86_64::_mm_min_epi32(x, min1) };
        let min3 = unsafe { std::arch::x86_64::_mm_shuffle_epi32(min2, std::arch::x86_64::_MM_SHUFFLE(0, 0, 0, 1)) };
        let min4 = unsafe { std::arch::x86_64::_mm_min_epi32(min2, min3) };
        let min_counter_val = unsafe { std::arch::x86_64::_mm_cvtsi128_si32(min4) };

        let ct_item = unsafe { std::arch::x86_64::_mm256_set1_epi32(min_counter_val) };
        let ct_matched = unsafe { std::arch::x86_64::_mm256_cmpeq_epi32(ct_item, std::mem::transmute(results)) };
        let matched = unsafe { std::arch::x86_64::_mm256_movemask_ps(std::mem::transmute(ct_matched)) };
        let min_counter = matched.trailing_zeros() as usize;

        if min_counter_val == 0 {
            self.buckets[pos].key[min_counter] = fp;
            self.buckets[pos].val[min_counter] = f;
            return 0;
        }

        let guard_val = self.buckets[pos].val[MAX_VALID_COUNTER];
        let guard_val = update_guard_val(guard_val);

        if !judge_if_swap(get_counter_val(min_counter_val), guard_val) {
            self.buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
            return 2;
        }

        swap_key.copy_from_slice(&self.buckets[pos].key[min_counter].to_ne_bytes());
        *swap_val = self.buckets[pos].val[min_counter];

        self.buckets[pos].val[MAX_VALID_COUNTER] = 0;
        self.buckets[pos].key[min_counter] = fp;
        self.buckets[pos].val[min_counter] = 0x80000001;

        return 1;
    }

    pub fn quick_insert(&mut self, key: &[u8], f: u32) -> i32 {
        let fp = u32::from_ne_bytes(key.try_into().unwrap());
        let pos = calculate_bucket_pos(fp) % BUCKET_NUM;

        let item = std::arch::x86_64::_mm256_set1_epi32(fp as i32);
        let keys_p = unsafe { &*(self.buckets[pos].key.as_ptr() as *const __m256i) };
        let matched = unsafe { std::arch::x86_64::_mm256_cmpeq_epi32(item, *keys_p) };
        let matched_mask = unsafe { std::arch::x86_64::_mm256_movemask_ps(std::mem::transmute(matched)) };

        if matched_mask != 0 {
            let matched_index = matched_mask.trailing_zeros() as usize;
            self.buckets[pos].val[matched_index] += f;
            return 0;
        }

        let mask_base = 0x7FFFFFFF;
        let counters = unsafe { &*(self.buckets[pos].val.as_ptr() as *const __m256i) };
        let masks = unsafe { std::arch::x86_64::_mm256_set1_epi32(mask_base as i32) };
        let results = unsafe { std::arch::x86_64::_mm256_and_ps(std::mem::transmute(*counters), std::mem::transmute(masks)) };
        let mask2 = unsafe { std::arch::x86_64::_mm256_set_epi32(mask_base as i32, 0, 0, 0, 0, 0, 0, 0) };
        let results = unsafe { std::arch::x86_64::_mm256_or_ps(results, std::mem::transmute(mask2)) };

        let low_part = unsafe { std::arch::x86_64::_mm256_extractf128_ps(results, 0) };
        let high_part = unsafe { std::arch::x86_64::_mm256_extractf128_ps(results, 1) };
        let x = unsafe { std::arch::x86_64::_mm_min_epi32(std::mem::transmute(low_part), std::mem::transmute(high_part)) };
        let min1 = unsafe { std::arch::x86_64::_mm_shuffle_epi32(x, std::arch::x86_64::_MM_SHUFFLE(0, 0, 3, 2)) };
        let min2 = unsafe { std::arch::x86_64::_mm_min_epi32(x, min1) };
        let min3 = unsafe { std::arch::x86_64::_mm_shuffle_epi32(min2, std::arch::x86_64::_MM_SHUFFLE(0, 0, 0, 1)) };
        let min4 = unsafe { std::arch::x86_64::_mm_min_epi32(min2, min3) };
        let min_counter_val = unsafe { std::arch::x86_64::_mm_cvtsi128_si32(min4) };

        let ct_item = unsafe { std::arch::x86_64::_mm256_set1_epi32(min_counter_val) };
        let ct_matched = unsafe { std::arch::x86_64::_mm256_cmpeq_epi32(ct_item, std::mem::transmute(results)) };
        let matched = unsafe { std::arch::x86_64::_mm256_movemask_ps(std::mem::transmute(ct_matched)) };
        let min_counter = matched.trailing_zeros() as usize;

        if min_counter_val == 0 {
            self.buckets[pos].key[min_counter] = fp;
            self.buckets[pos].val[min_counter] = f;
            return 0;
        }

        let guard_val = self.buckets[pos].val[MAX_VALID_COUNTER];
        let guard_val = update_guard_val(guard_val);

        if !judge_if_swap(min_counter_val, guard_val) {
            self.buckets[pos].val[MAX_VALID_COUNTER] = guard_val;
            return 2;
        }

        self.buckets[pos].val[MAX_VALID_COUNTER] = 0;
        self.buckets[pos].key[min_counter] = fp;
        return 1;
    }

    pub fn query(&self, key: &[u8]) -> u32 {
        let fp = u32::from_ne_bytes(key.try_into().unwrap());
        let pos = calculate_bucket_pos(fp) % BUCKET_NUM;

        for i in 0..MAX_VALID_COUNTER {
            if self.buckets[pos].key[i] == fp {
                return self.buckets[pos].val[i];
            }
        }
        0
    }

    pub fn get_memory_usage(&self) -> usize {
        BUCKET_NUM * size_of::<Bucket>()
    }

    pub fn get_bucket_num(&self) -> usize {
        BUCKET_NUM
    }
}