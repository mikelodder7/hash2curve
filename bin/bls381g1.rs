use hash2curve::prelude::*;
use std::{
    io::{stdout, Write},
    time::{Duration, Instant},
};

fn main() {
    let blocks = 7;
    let timeout_secs = 3;

    let dst = DomainSeparationTag::new(
        b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        Some(b"BENCHMARKS"),
        None,
        None,
    )
    .unwrap();
    let hasher = Bls12381G1Sswu::new(dst);

    let block_byte_sizes = [16, 64, 256, 1024, 8192, 16384, 65535];
    for i in 0..blocks {
        let mut data = vec![0u8; block_byte_sizes[i]];

        print!(
            "Doing bls12-381-g1-sswu-hash-to-curve-xmd-sha256 for {}s on message size {}: ",
            timeout_secs, block_byte_sizes[i]
        );
        stdout().flush().unwrap();

        let (counts, elapsed) = hash_loop(data.as_mut_slice(), &hasher, timeout_secs);

        println!(
            "{} in {}.{:0<2}s. {:0.3} ms/iter",
            counts,
            elapsed / 1000,
            (elapsed % 1000) / 10,
            ((elapsed as f64 / 1000f64) / counts as f64) * 1000.00
        );
    }
}

fn hash_loop(data: &mut [u8], hasher: &Bls12381G1Sswu, timeout_secs: u64) -> (u64, u64) {
    let mut count = 0u64;
    let timer = Instant::now();

    loop {
        let _ = hasher.hash_to_curve_xmd::<sha2::Sha256>(&data).unwrap();

        count += 1;

        if timer.elapsed() >= Duration::from_secs(timeout_secs) {
            break;
        }
    }

    let elapsed = timer.elapsed().as_secs() * 1000 + timer.elapsed().subsec_millis() as u64;

    (count, elapsed)
}
