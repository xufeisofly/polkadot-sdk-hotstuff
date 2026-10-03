#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

use rand::Rng;
use sc_consensus_hotstuff_bls::*;

macro_rules! bench_verify {
    ($name:ident, $num:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let rng = &mut rand::rng();
            // generate private keys
            let private_keys: Vec<_> = (0..$num).map(|_| PrivateKey::generate(rng)).collect();

            // generate messages
            let messages: Vec<Vec<u8>> = (0..$num)
                .map(|_| (0..64).map(|_| rng.random()).collect())
                .collect();

            // sign messages
            let sigs = messages
                .iter()
                .zip(&private_keys)
                .map(|(message, pk)| pk.sign(message))
                .collect::<Vec<Signature>>();

            let aggregated_signature = aggregate(&sigs).unwrap();

            let hashes = messages
                .iter()
                .map(|message| hash(message))
                .collect::<Vec<_>>();
            let public_keys = private_keys
                .iter()
                .map(|pk| pk.public_key())
                .collect::<Vec<_>>();

            b.iter(|| black_box(verify(&aggregated_signature, &hashes, &public_keys)))
        }
    };
}

macro_rules! bench_verify_aggregated {
    ($name:ident, $num:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let rng = &mut rand::rng();
            let private_keys: Vec<_> = (0..$num).map(|_| PrivateKey::generate(rng)).collect();

            let messages: Vec<Vec<u8>> = (0..$num)
                .map(|_| (0..64).map(|_| rng.random()).collect())
                .collect();

            let sigs = messages
                .iter()
                .zip(&private_keys)
                .map(|(message, pk)| pk.sign(message))
                .collect::<Vec<Signature>>();

            let aggregated_signature = aggregate(&sigs).unwrap();
            let public_keys = private_keys
                .iter()
                .map(|pk| pk.public_key())
                .collect::<Vec<_>>();
            let message_refs: Vec<_> = messages.iter().map(|m| &m[..]).collect();

            b.iter(|| {
                black_box(verify_aggregated(
                    &aggregated_signature,
                    &message_refs,
                    &public_keys,
                ))
            })
        }
    };
}

macro_rules! bench_fast_verify_aggregated {
    ($name:ident, $num:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let rng = &mut rand::rng();
            // generate private keys
            let private_keys: Vec<_> = (0..$num).map(|_| PrivateKey::generate(rng)).collect();
            let message: Vec<u8> = (0..32).map(|_| rng.random()).collect();
            let signatures: Vec<_> = private_keys.iter().map(|sk| sk.sign(&message)).collect();
            let aggregated_signature = aggregate(&signatures).unwrap();

            let public_keys = private_keys
                .iter()
                .map(|pk| pk.public_key())
                .collect::<Vec<_>>();

            b.iter(|| {
                black_box(fast_verify_aggregated(
                    &aggregated_signature,
                    &message,
                    &public_keys,
                ))
            })
        }
    };
}

bench_verify!(bench_verify_1, 1);
bench_verify!(bench_verify_10, 10);
bench_verify!(bench_verify_100, 100);

bench_verify_aggregated!(bench_verify_aggregated_1, 1);
bench_verify_aggregated!(bench_verify_aggregated_10, 10);
bench_verify_aggregated!(bench_verify_aggregated_100, 100);

bench_fast_verify_aggregated!(bench_fast_verify_aggregated_1, 1);
bench_fast_verify_aggregated!(bench_fast_verify_aggregated_10, 10);
bench_fast_verify_aggregated!(bench_fast_verify_aggregated_100, 100);

/*
Result:

blst + multicore
test bench_fast_verify_aggregated_1   ... bench:     562,785.40 ns/iter (+/- 14,931.43)
test bench_fast_verify_aggregated_10  ... bench:     660,210.16 ns/iter (+/- 17,343.60)
test bench_fast_verify_aggregated_100 ... bench:     701,634.38 ns/iter (+/- 75,743.76)
test bench_verify_1                   ... bench:     449,023.96 ns/iter (+/- 12,577.19)
test bench_verify_10                  ... bench:     763,475.00 ns/iter (+/- 77,447.83)
test bench_verify_100                 ... bench:   2,478,543.75 ns/iter (+/- 351,917.28)
test bench_verify_aggregated_1        ... bench:     552,510.40 ns/iter (+/- 38,354.82)
test bench_verify_aggregated_10       ... bench:     881,458.85 ns/iter (+/- 45,114.94)
test bench_verify_aggregated_100      ... bench:   3,474,968.80 ns/iter (+/- 374,964.59)

pairing + multicore
test bench_fast_verify_aggregated_1   ... bench:   1,211,084.40 ns/iter (+/- 34,776.04)
test bench_fast_verify_aggregated_10  ... bench:   1,315,545.82 ns/iter (+/- 84,012.39)
test bench_fast_verify_aggregated_100 ... bench:   1,338,815.62 ns/iter (+/- 87,071.72)
test bench_verify_1                   ... bench:     965,417.71 ns/iter (+/- 51,462.60)
test bench_verify_10                  ... bench:   1,477,092.70 ns/iter (+/- 76,446.47)
test bench_verify_100                 ... bench:   6,161,166.65 ns/iter (+/- 897,723.92)
test bench_verify_aggregated_1        ... bench:   1,229,912.50 ns/iter (+/- 28,247.85)
test bench_verify_aggregated_10       ... bench:   2,065,280.20 ns/iter (+/- 97,865.96)
test bench_verify_aggregated_100      ... bench:   9,798,554.10 ns/iter (+/- 2,269,976.72)
 */
