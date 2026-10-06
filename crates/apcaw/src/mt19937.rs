// SPDX-License-Identifier: BSD-2-Clause
//! MT19937 with numpy's legacy `RandomState` seeding and `shuffle` (format §2).
//!
//! Only the pieces the layout needs: `init_genrand` seeding (what
//! `RandomState(int)` does), the tempered 32-bit output, numpy's
//! `random_interval` (masked rejection) and the legacy Fisher–Yates shuffle.

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER: u32 = 0x8000_0000;
const LOWER: u32 = 0x7fff_ffff;

/// MT19937 state seeded like `numpy.random.RandomState(seed)` for an integer seed.
#[derive(Clone)]
pub struct Mt19937 {
    mt: [u32; N],
    idx: usize,
}

impl Mt19937 {
    /// `init_genrand(seed)`, the seeding numpy's legacy `RandomState` uses for integer seeds.
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; N];
        let mut s = seed;
        for (pos, slot) in mt.iter_mut().enumerate() {
            *slot = s;
            s = 1_812_433_253u32.wrapping_mul(s ^ (s >> 30)).wrapping_add(pos as u32 + 1);
        }
        Mt19937 { mt, idx: N }
    }

    fn twist(&mut self) {
        for i in 0..N {
            let y = (self.mt[i] & UPPER) | (self.mt[(i + 1) % N] & LOWER);
            let mag = if y & 1 == 1 { MATRIX_A } else { 0 };
            self.mt[i] = self.mt[(i + M) % N] ^ (y >> 1) ^ mag;
        }
        self.idx = 0;
    }

    /// Next tempered 32-bit output.
    pub fn next_u32(&mut self) -> u32 {
        if self.idx >= N {
            self.twist();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// numpy `random_interval(max)`: uniform on `0..=max` by masked rejection.
    pub fn interval(&mut self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        let mut mask = max;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        loop {
            let v = self.next_u32() & mask;
            if v <= max {
                return v;
            }
        }
    }

    /// numpy legacy `RandomState.shuffle` of a 1-d array.
    pub fn shuffle<T>(&mut self, a: &mut [T]) {
        assert!(a.len() <= u32::MAX as usize, "shuffle length exceeds 32 bits");
        for i in (1..a.len()).rev() {
            let j = self.interval(i as u32) as usize;
            a.swap(i, j);
        }
    }
}
