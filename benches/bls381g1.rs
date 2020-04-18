#[macro_use]
extern crate criterion;

#[cfg(feature = "bls")]
use criterion::Criterion;
#[cfg(feature = "bls")]
use hash2curve::prelude::*;

#[cfg(feature = "bls")]
fn bls381g1hash_benchmark(c: &mut Criterion) {
    c.bench_function("Test hashing 2048 bytes", move |b| {
        let dst = DomainSeparationTag::new(
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Some(b"BENCHMARKS"),
            None,
            None,
        )
        .unwrap();
        let hasher = Bls12381G1Sswu::new(dst);
        let mut data = [0u8; 2048];
        b.iter(move || {
            hasher.hash_to_curve_xmd::<sha2::Sha256>(&data[..]);
        });
    });
}

#[cfg(feature = "bls")]
criterion_group!(
    name = bench_bls381g1;
    config = Criterion::default();
    targets = bls381g1hash_benchmark
);

#[cfg(feature = "bls")]
criterion_main!(bench_bls381g1);
