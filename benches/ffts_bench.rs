use criterion::Throughput;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curv::cryptographic_primitives::secret_sharing::{ffts::multiply_polynomials, Polynomial};
use curv::elliptic::curves::{Scalar, Secp256k1};
use std::time::Instant;

fn criterion_benchmark(c: &mut Criterion) {
    let fft_sizes = vec![
        2,
        4,
        8,
        16,
        32,
        32 * 3,
        149,
        149 * 2,
        149 * 4,
        149 * 8,
        149 * 16,
        149 * 32,
        149 * 2 * 3,
        149 * 4 * 3,
        149 * 8 * 3,
        149 * 16 * 3,
        32 * 3 * 149,
        // 32 * 3 * 149 * 631,
    ];
    let mut group = c.benchmark_group("multiply_polynomials");
    for size in fft_sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(10);
        group.bench_with_input(
            BenchmarkId::new("multiply_polynomials", size),
            &size,
            |bench, &size| {
                bench.iter_custom(move |iters| {
                    let a_polys: Vec<Polynomial<Secp256k1>> = (0..iters)
                        .map(|_| {
                            Polynomial::from_coefficients(
                                (0..size).map(|_| Scalar::random()).collect(),
                            )
                        })
                        .collect();
                    let b_polys: Vec<Polynomial<Secp256k1>> = (0..iters)
                        .map(|_| {
                            Polynomial::from_coefficients(
                                (0..size).map(|_| Scalar::random()).collect(),
                            )
                        })
                        .collect();
                    let start = Instant::now();
                    a_polys
                        .into_iter()
                        .zip(b_polys.into_iter())
                        .for_each(|(a, b)| {
                            multiply_polynomials(a, b);
                        });
                    start.elapsed()
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
