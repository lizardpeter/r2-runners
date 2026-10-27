// Rust 1.99.1, edition 2024. Mirrors bench.cpp's inputs and arithmetic.
use std::hint::black_box;
use std::time::Instant;

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn hash_mix(seed: u64) -> u64 {
    let mut state = seed ^ 0xdedab00b15c0ffee;
    let mut acc = 0u64;
    for i in 0u64..6_000_000 {
        state = splitmix64(state ^ i);
        acc ^= state.rotate_left((i & 63) as u32);
    }
    acc
}

fn scan(seed: u64) -> u64 {
    const N: usize = 4_194_304;
    let mut v = vec![0u32; N];
    let offset = (seed as u32).wrapping_mul(1_013_904_223);
    for (i, item) in v.iter_mut().enumerate() {
        *item = (i as u32).wrapping_mul(1_664_525).wrapping_add(offset);
    }
    let mut sum = 0u64;
    for round in 0u32..6 {
        for &x in &v {
            if (x & 7) == round {
                sum = sum.wrapping_add((x as u64) ^ (round as u64));
            }
        }
    }
    sum
}

fn random_gather(seed: u64) -> u64 {
    const N: usize = 1_048_576;
    let mut v = vec![0u32; N];
    let offset = (seed as u32).wrapping_mul(1_013_904_223);
    for (i, item) in v.iter_mut().enumerate() {
        *item = (i as u32).wrapping_mul(1_664_525).wrapping_add(offset);
    }
    let mut state = (seed | 1) ^ 0x9e3779b97f4a7c15;
    let mut sum = 0u64;
    for _ in 0..8_000_000u32 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sum = sum.wrapping_add(v[(state as usize) & (N - 1)] as u64);
    }
    sum
}

fn integer_sort(seed: u64) -> u64 {
    const N: usize = 200_000;
    let mut v = vec![0u32; N];
    let mut state = seed ^ 0xabcd1234beef9876;
    for item in &mut v {
        state = splitmix64(state);
        *item = (state >> 32) as u32;
    }
    v.sort_unstable();
    let mut sum = 0u64;
    for i in (0..N).step_by(997) {
        sum = sum.wrapping_add((v[i] as u64).wrapping_mul(i as u64 + 1));
    }
    sum
}

fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    let task = args.next().expect("usage: bench <hash|scan|gather|sort> <seed>");
    let seed: u64 = args.next().expect("missing seed").parse().expect("integer seed");
    let seed = black_box(seed);
    let start = Instant::now();
    let result = match task.as_str() {
        "hash" => hash_mix(seed),
        "scan" => scan(seed),
        "gather" => random_gather(seed),
        "sort" => integer_sort(seed),
        _ => panic!("invalid task"),
    };
    let elapsed = start.elapsed().as_nanos();
    println!("checksum={result:016x}\nelapsed_ns={elapsed}");
}
