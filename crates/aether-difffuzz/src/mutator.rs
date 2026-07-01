//! Mutation engine: byte-level mutations on a seed corpus.
//!
//! Implements the core operators from AFL/libFuzzer:
//!   - BitFlip, ByteFlip, ByteInsert, ByteDelete, ByteReplace, Splice,
//!     InterestingByte, Truncate, Repeat.
//!
//! The RNG is a simple xorshift64 so the fuzzer is reproducible given a seed.

use serde::{Deserialize, Serialize};

/// A deterministic xorshift64 PRNG.
pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        Xorshift64 {
            state: if seed == 0 { 0xdeadbeef_cafebabe } else { seed },
        }
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        (self.next() as usize) % limit
    }

    pub fn next_u8(&mut self) -> u8 {
        self.next() as u8
    }

    pub fn next_bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// Interesting byte values that often trigger edge cases.
const INTERESTING_BYTES: &[u8] = &[0, 1, 0x7f, 0x80, 0xfe, 0xff, b'\n', b'\r', b'"', b'\0'];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationOp {
    BitFlip { pos: usize, bit: u8 },
    ByteFlip { pos: usize },
    ByteInsert { pos: usize, value: u8 },
    ByteDelete { pos: usize },
    ByteReplace { pos: usize, value: u8 },
    InterestingByte { pos: usize, value: u8 },
    Truncate { new_len: usize },
    Repeat { pos: usize, count: usize },
    Splice { other_idx: usize },
}

/// Mutator over a corpus of seed inputs.
pub struct Mutator {
    pub corpus: Vec<Vec<u8>>,
    rng: Xorshift64,
    pub mutations_per_input: usize,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Mutator {
            corpus: vec![b"hello".to_vec(), vec![0u8; 8], b"{}".to_vec()],
            rng: Xorshift64::new(seed),
            mutations_per_input: 4,
        }
    }

    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.corpus.push(seed);
    }

    /// Pick a random corpus entry and apply `mutations_per_input` mutations.
    pub fn next_input(&mut self) -> (Vec<u8>, Vec<MutationOp>) {
        let idx = self.rng.next_usize(self.corpus.len());
        let mut data = self.corpus[idx].clone();
        let mut ops = Vec::new();

        for _ in 0..self.mutations_per_input {
            if let Some(op) = self.mutate_once(&mut data, idx) {
                ops.push(op);
            }
        }
        (data, ops)
    }

    fn mutate_once(&mut self, data: &mut Vec<u8>, corpus_idx: usize) -> Option<MutationOp> {
        if data.is_empty() {
            data.push(self.rng.next_u8());
            return Some(MutationOp::ByteInsert { pos: 0, value: data[0] });
        }
        let choice = self.rng.next_usize(9);
        match choice {
            0 => {
                // BitFlip
                let pos = self.rng.next_usize(data.len());
                let bit = 1u8 << (self.rng.next_usize(8) as u8);
                data[pos] ^= bit;
                Some(MutationOp::BitFlip { pos, bit })
            }
            1 => {
                // ByteFlip
                let pos = self.rng.next_usize(data.len());
                data[pos] = !data[pos];
                Some(MutationOp::ByteFlip { pos })
            }
            2 if data.len() < 65536 => {
                // ByteInsert
                let pos = self.rng.next_usize(data.len() + 1);
                let value = self.rng.next_u8();
                data.insert(pos, value);
                Some(MutationOp::ByteInsert { pos, value })
            }
            3 => {
                // ByteDelete
                let pos = self.rng.next_usize(data.len());
                data.remove(pos);
                Some(MutationOp::ByteDelete { pos })
            }
            4 => {
                // ByteReplace
                let pos = self.rng.next_usize(data.len());
                let value = self.rng.next_u8();
                data[pos] = value;
                Some(MutationOp::ByteReplace { pos, value })
            }
            5 => {
                // InterestingByte
                let pos = self.rng.next_usize(data.len());
                let value = INTERESTING_BYTES[self.rng.next_usize(INTERESTING_BYTES.len())];
                data[pos] = value;
                Some(MutationOp::InterestingByte { pos, value })
            }
            6 if data.len() > 1 => {
                // Truncate
                let new_len = self.rng.next_usize(data.len() - 1) + 1;
                data.truncate(new_len);
                Some(MutationOp::Truncate { new_len })
            }
            7 => {
                // Repeat a byte
                let pos = self.rng.next_usize(data.len());
                let count = self.rng.next_usize(8) + 1;
                let byte = data[pos];
                for _ in 0..count {
                    if data.len() >= 65536 {
                        break;
                    }
                    data.insert(pos, byte);
                }
                Some(MutationOp::Repeat { pos, count })
            }
            8 if self.corpus.len() > 1 => {
                // Splice with another corpus entry
                let other_idx = {
                    let mut i = self.rng.next_usize(self.corpus.len());
                    if i == corpus_idx {
                        i = (i + 1) % self.corpus.len();
                    }
                    i
                };
                let other = self.corpus[other_idx].clone();
                if !other.is_empty() {
                    let split = self.rng.next_usize(data.len().min(other.len()));
                    data.truncate(split);
                    data.extend_from_slice(&other[split..]);
                }
                Some(MutationOp::Splice { other_idx })
            }
            _ => None,
        }
    }

    /// Add a diverging input to the corpus for further mutation.
    pub fn add_to_corpus(&mut self, input: Vec<u8>) {
        if self.corpus.len() < 10_000 {
            self.corpus.push(input);
        }
    }
}
