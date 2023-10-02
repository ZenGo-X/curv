//! This module entirely and shamelessly copypasted from [num-bigint-dig] crate with slight
//! changes to make it work with num_bigint::BigInt
//!
//! [num-bigint-dig]: https://docs.rs/num-bigint-dig/0.6.1/src/num_bigint_dig/prime.rs.html#113-179

#![allow(clippy::many_single_char_names)]

use std::hash::Hash;

use rand::{rngs::StdRng, Rng, SeedableRng};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::*;

lazy_static::lazy_static! {
    static ref BIG_1: BigUint = BigUint::from(1u32);
    static ref BIG_2: BigUint = BigUint::from(2u32);
    static ref BIG_3: BigUint = BigUint::from(3u32);
    static ref BIG_5: BigUint = BigUint::from(5u32);
    static ref BIG_7: BigUint = BigUint::from(7u32);
    static ref BIG_64: BigUint = BigUint::from(64u32);
}

const NUMBER_OF_PRIMES: u64 = 127;

const PRIME_GAP: [u64; 167] = [
    2, 2, 4, 2, 4, 2, 4, 6, 2, 6, 4, 2, 4, 6, 6, 2, 6, 4, 2, 6, 4, 6, 8, 4, 2, 4, 2, 4, 14, 4, 6,
    2, 10, 2, 6, 6, 4, 6, 6, 2, 10, 2, 4, 2, 12, 12, 4, 2, 4, 6, 2, 10, 6, 6, 6, 2, 6, 4, 2, 10,
    14, 4, 2, 4, 14, 6, 10, 2, 4, 6, 8, 6, 6, 4, 6, 8, 4, 8, 10, 2, 10, 2, 6, 4, 6, 8, 4, 2, 4, 12,
    8, 4, 8, 4, 6, 12, 2, 18, 6, 10, 6, 6, 2, 6, 10, 6, 6, 2, 6, 6, 4, 2, 12, 10, 2, 4, 6, 6, 2,
    12, 4, 6, 8, 10, 8, 10, 8, 6, 6, 4, 8, 6, 4, 8, 4, 14, 10, 12, 2, 10, 2, 4, 2, 10, 14, 4, 2, 4,
    14, 4, 2, 4, 20, 4, 8, 10, 8, 4, 6, 6, 14, 4, 6, 6, 8, 6, 12,
];

const INCR_LIMIT: usize = 0x10000;

const PRIME_BIT_MASK: u64 = 1 << 2
    | 1 << 3
    | 1 << 5
    | 1 << 7
    | 1 << 11
    | 1 << 13
    | 1 << 17
    | 1 << 19
    | 1 << 23
    | 1 << 29
    | 1 << 31
    | 1 << 37
    | 1 << 41
    | 1 << 43
    | 1 << 47
    | 1 << 53
    | 1 << 59
    | 1 << 61;

const PRIMES_A: u64 = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37;
const PRIMES_B: u64 = 29 * 31 * 41 * 43 * 47 * 53;

/// ProbablyPrime reports whether x is probably prime,
/// applying the Miller-Rabin test with n pseudorandomly chosen bases
/// as well as a Baillie-PSW test.
///
/// If x is prime, ProbablyPrime returns true.
/// If x is chosen randomly and not prime, ProbablyPrime probably returns false.
/// The probability of returning true for a randomly chosen non-prime is at most ¼ⁿ.
///
/// ProbablyPrime is 100% accurate for inputs less than 2⁶⁴.
/// See Menezes et al., Handbook of Applied Cryptography, 1997, pp. 145-149,
/// and FIPS 186-4 Appendix F for further discussion of the error probabilities.
///
/// ProbablyPrime is not suitable for judging primes that an adversary may
/// have crafted to fool the test.
///
/// This is a port of `ProbablyPrime` from the go std lib.
pub fn probably_prime(x: &BigUint, n: usize) -> bool {
    if x.is_zero() {
        return false;
    }

    if x < &*BIG_64 {
        return (PRIME_BIT_MASK & (1 << x.to_u64().unwrap())) != 0;
    }

    if x.is_even() {
        return false;
    }

    let r_a = &(x % PRIMES_A);
    let r_b = &(x % PRIMES_B);

    if (r_a % 3u32).is_zero()
        || (r_a % 5u32).is_zero()
        || (r_a % 7u32).is_zero()
        || (r_a % 11u32).is_zero()
        || (r_a % 13u32).is_zero()
        || (r_a % 17u32).is_zero()
        || (r_a % 19u32).is_zero()
        || (r_a % 23u32).is_zero()
        || (r_a % 37u32).is_zero()
        || (r_b % 29u32).is_zero()
        || (r_b % 31u32).is_zero()
        || (r_b % 41u32).is_zero()
        || (r_b % 43u32).is_zero()
        || (r_b % 47u32).is_zero()
        || (r_b % 53u32).is_zero()
    {
        return false;
    }

    probably_prime_miller_rabin(x, n + 1, true) && probably_prime_lucas(x)
}

/// Reports whether n passes reps rounds of the Miller-Rabin primality test, using pseudo-randomly chosen bases.
/// If `force2` is true, one of the rounds is forced to use base 2.
///
/// See Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
pub fn probably_prime_miller_rabin(n: &BigUint, reps: usize, force2: bool) -> bool {
    // println!("miller-rabin: {}", n);
    let nm1 = n - &*BIG_1;
    // determine q, k such that nm1 = q << k
    let k = nm1.trailing_zeros().unwrap() as usize;
    let q = &nm1 >> k;
    let nm3 = n - &*BIG_3;

    // Get seed for the random by hashing n
    struct Hasher([u8; 32]);
    impl std::hash::Hasher for Hasher {
        fn finish(&self) -> u64 {
            unreachable!("we do not call this method")
        }

        fn write(&mut self, bytes: &[u8]) {
            for (i, chunk) in bytes.chunks(16).enumerate() {
                let i = if i & 1 == 1 { 16 } else { 0 };

                let mut a = [0u8; 16];
                a.copy_from_slice(&self.0[i..i + 16]);

                let mut b = [0u8; 16];
                (&mut b[..chunk.len()]).copy_from_slice(chunk);

                let c = (u128::from_ne_bytes(a) ^ u128::from_ne_bytes(b)).to_ne_bytes();
                (&mut self.0[i..i + 16]).copy_from_slice(&c[..]);
            }
        }
    }
    let mut hasher = Hasher([0; 32]);
    n.hash(&mut hasher);
    let seed = hasher.0;
    let mut rng = StdRng::from_seed(seed);

    'nextrandom: for i in 0..reps {
        let x = if i == reps - 1 && force2 {
            BIG_2.clone()
        } else {
            gen_biguint_below(&mut rng, &nm3) + &*BIG_2
        };

        let mut y = x.modpow(&q, n);
        if y.is_one() || y == nm1 {
            continue;
        }

        for _ in 1..k {
            y = y.modpow(&*BIG_2, n);
            if y == nm1 {
                break 'nextrandom;
            }
            if y.is_one() {
                return false;
            }
        }
        return false;
    }

    true
}

/// Reports whether n passes the "almost extra strong" Lucas probable prime test,
/// using Baillie-OEIS parameter selection. This corresponds to "AESLPSP" on Jacobsen's tables (link below).
/// The combination of this test and a Miller-Rabin/Fermat test with base 2 gives a Baillie-PSW test.
///
///
/// References:
///
/// Baillie and Wagstaff, "Lucas Pseudoprimes", Mathematics of Computation 35(152),
/// October 1980, pp. 1391-1417, especially page 1401.
/// http://www.ams.org/journals/mcom/1980-35-152/S0025-5718-1980-0583518-6/S0025-5718-1980-0583518-6.pdf
///
/// Grantham, "Frobenius Pseudoprimes", Mathematics of Computation 70(234),
/// March 2000, pp. 873-891.
/// http://www.ams.org/journals/mcom/2001-70-234/S0025-5718-00-01197-2/S0025-5718-00-01197-2.pdf
///
/// Baillie, "Extra strong Lucas pseudoprimes", OEIS A217719, https://oeis.org/A217719.
///
/// Jacobsen, "Pseudoprime Statistics, Tables, and Data", http://ntheory.org/pseudoprimes.html.
///
/// Nicely, "The Baillie-PSW Primality Test", http://www.trnicely.net/misc/bpsw.html.
/// (Note that Nicely's definition of the "extra strong" test gives the wrong Jacobi condition,
/// as pointed out by Jacobsen.)
///
/// Crandall and Pomerance, Prime Numbers: A Computational Perspective, 2nd ed.
/// Springer, 2005.
pub fn probably_prime_lucas(n: &BigUint) -> bool {
    // println!("lucas: {}", n);
    // Discard 0, 1.
    if n.is_zero() || n.is_one() {
        return false;
    }

    // Two is the only even prime.
    if n.to_u64() == Some(2) {
        return false;
    }

    // Baillie-OEIS "method C" for choosing D, P, Q,
    // as in https://oeis.org/A217719/a217719.txt:
    // try increasing P ≥ 3 such that D = P² - 4 (so Q = 1)
    // until Jacobi(D, n) = -1.
    // The search is expected to succeed for non-square n after just a few trials.
    // After more than expected failures, check whether n is square
    // (which would cause Jacobi(D, n) = 1 for all D not dividing n).
    let mut p = 3u64;
    let n_int = BigInt::from_biguint(Sign::Plus, n.clone());

    loop {
        if p > 10000 {
            // This is widely believed to be impossible.
            // If we get a report, we'll want the exact number n.
            panic!("internal error: cannot find (D/n) = -1 for {:?}", n)
        }

        let j = jacobi(&BigInt::from(p * p - 4), &n_int);

        if j == -1 {
            break;
        }
        if j == 0 {
            // d = p²-4 = (p-2)(p+2).
            // If (d/n) == 0 then d shares a prime factor with n.
            // Since the loop proceeds in increasing p and starts with p-2==1,
            // the shared prime factor must be p+2.
            // If p+2 == n, then n is prime; otherwise p+2 is a proper factor of n.
            return n_int.to_i64() == Some(p as i64 + 2);
        }

        // We'll never find (d/n) = -1 if n is a square.
        // If n is a non-square we expect to find a d in just a few attempts on average.
        // After 40 attempts, take a moment to check if n is indeed a square.

        let t1 = &n_int * &n_int;
        if p == 40 && t1.sqrt() == n_int {
            return false;
        }

        p += 1;
    }

    // Grantham definition of "extra strong Lucas pseudoprime", after Thm 2.3 on p. 876
    // (D, P, Q above have become Δ, b, 1):
    //
    // Let U_n = U_n(b, 1), V_n = V_n(b, 1), and Δ = b²-4.
    // An extra strong Lucas pseudoprime to base b is a composite n = 2^r s + Jacobi(Δ, n),
    // where s is odd and gcd(n, 2*Δ) = 1, such that either (i) U_s ≡ 0 mod n and V_s ≡ ±2 mod n,
    // or (ii) V_{2^t s} ≡ 0 mod n for some 0 ≤ t < r-1.
    //
    // We know gcd(n, Δ) = 1 or else we'd have found Jacobi(d, n) == 0 above.
    // We know gcd(n, 2) = 1 because n is odd.
    //
    // Arrange s = (n - Jacobi(Δ, n)) / 2^r = (n+1) / 2^r.
    let mut s = n + &*BIG_1;
    let r = s.trailing_zeros().unwrap() as usize;
    s = &s >> r;
    let nm2 = n - &*BIG_2; // n - 2

    // We apply the "almost extra strong" test, which checks the above conditions
    // except for U_s ≡ 0 mod n, which allows us to avoid computing any U_k values.
    // Jacobsen points out that maybe we should just do the full extra strong test:
    // "It is also possible to recover U_n using Crandall and Pomerance equation 3.13:
    // U_n = D^-1 (2V_{n+1} - PV_n) allowing us to run the full extra-strong test
    // at the cost of a single modular inversion. This computation is easy and fast in GMP,
    // so we can get the full extra-strong test at essentially the same performance as the
    // almost extra strong test."

    // Compute Lucas sequence V_s(b, 1), where:
    //
    //	V(0) = 2
    //	V(1) = P
    //	V(k) = P V(k-1) - Q V(k-2).
    //
    // (Remember that due to method C above, P = b, Q = 1.)
    //
    // In general V(k) = α^k + β^k, where α and β are roots of x² - Px + Q.
    // Crandall and Pomerance (p.147) observe that for 0 ≤ j ≤ k,
    //
    //	V(j+k) = V(j)V(k) - V(k-j).
    //
    // So in particular, to quickly double the subscript:
    //
    //	V(2k) = V(k)² - 2
    //	V(2k+1) = V(k) V(k+1) - P
    //
    // We can therefore start with k=0 and build up to k=s in log₂(s) steps.
    let mut vk = BIG_2.clone();
    let mut vk1 = BigUint::from_u64(p).unwrap();

    for i in (0..s.bits() as usize).rev() {
        if is_bit_set(&s, i) {
            // k' = 2k+1
            // V(k') = V(2k+1) = V(k) V(k+1) - P
            let t1 = (&vk * &vk1) + n - p;
            vk = &t1 % n;
            // V(k'+1) = V(2k+2) = V(k+1)² - 2
            let t1 = (&vk1 * &vk1) + &nm2;
            vk1 = &t1 % n;
        } else {
            // k' = 2k
            // V(k'+1) = V(2k+1) = V(k) V(k+1) - P
            let t1 = (&vk * &vk1) + n - p;
            vk1 = &t1 % n;
            // V(k') = V(2k) = V(k)² - 2
            let t1 = (&vk * &vk) + &nm2;
            vk = &t1 % n;
        }
    }

    // Now k=s, so vk = V(s). Check V(s) ≡ ±2 (mod n).
    if vk.to_u64() == Some(2) || vk == nm2 {
        // Check U(s) ≡ 0.
        // As suggested by Jacobsen, apply Crandall and Pomerance equation 3.13:
        //
        //	U(k) = D⁻¹ (2 V(k+1) - P V(k))
        //
        // Since we are checking for U(k) == 0 it suffices to check 2 V(k+1) == P V(k) mod n,
        // or P V(k) - 2 V(k+1) == 0 mod n.
        let mut t1 = &vk * p;
        let mut t2 = &vk1 << 1;

        if t1 < t2 {
            core::mem::swap(&mut t1, &mut t2);
        }

        t1 -= t2;

        if (t1 % n).is_zero() {
            return true;
        }
    }

    // Check V(2^t s) ≡ 0 mod n for some 0 ≤ t < r-1.
    for _ in 0..r - 1 {
        if vk.is_zero() {
            return true;
        }

        // Optimization: V(k) = 2 is a fixed point for V(k') = V(k)² - 2,
        // so if V(k) = 2, we can stop: we will never find a future V(k) == 0.
        if vk.to_u64() == Some(2) {
            return false;
        }

        // k' = 2k
        // V(k') = V(2k) = V(k)² - 2
        let t1 = (&vk * &vk) - &*BIG_2;
        vk = &t1 % n;
    }

    false
}

/// Calculate the next larger prime, given a starting number `n`.
pub fn next_prime(n: &BigUint) -> BigUint {
    if n < &*BIG_2 {
        return BIG_2.clone();
    }

    // We want something larger than our current number.
    let mut res = n + &*BIG_1;

    // Ensure we are odd.
    res |= &*BIG_1;

    // Handle values up to 7.
    if let Some(val) = res.to_u64() {
        if val < 7 {
            return res;
        }
    }

    let nbits = res.bits();
    let prime_limit = if nbits / 2 >= NUMBER_OF_PRIMES {
        NUMBER_OF_PRIMES - 1
    } else {
        nbits / 2
    } as usize;

    // Compute the residues modulo small odd primes
    let mut moduli = vec![BigUint::zero(); prime_limit];

    'outer: loop {
        let mut prime = 3;
        for i in 0..prime_limit {
            moduli[i] = &res / prime;
            prime += PRIME_GAP[i];
        }

        // Check residues
        let mut difference: usize = 0;
        for incr in (0..INCR_LIMIT as u64).step_by(2) {
            let mut prime: u64 = 3;

            let mut cancel = false;
            for i in 0..prime_limit {
                let r = (&moduli[i] + incr) % prime;
                prime += PRIME_GAP[i];

                if r.is_zero() {
                    cancel = true;
                    break;
                }
            }

            if !cancel {
                res += difference;
                difference = 0;
                if probably_prime(&res, 20) {
                    break 'outer;
                }
            }

            difference += 2;
        }

        res += difference;
    }

    res
}

/// Jacobi returns the Jacobi symbol (x/y), either +1, -1, or 0.
/// The y argument must be an odd integer.
pub fn jacobi(x: &BigInt, y: &BigInt) -> isize {
    if !y.is_odd() {
        panic!(
            "invalid arguments, y must be an odd integer,but got {:?}",
            y
        );
    }

    let mut a = x.clone();
    let mut b = y.clone();
    let mut j = 1;

    if b.is_negative() {
        if a.is_negative() {
            j = -1;
        }
        b = -b;
    }

    loop {
        if b.is_one() {
            return j;
        }
        if a.is_zero() {
            return 0;
        }

        a = a.mod_floor(&b);
        if a.is_zero() {
            return 0;
        }

        // a > 0

        // handle factors of 2 in a
        let s = a.trailing_zeros().unwrap();
        if s & 1 != 0 {
            let bmod8 = (&b & BigInt::from(7)).to_u64().unwrap();
            if bmod8 == 3 || bmod8 == 5 {
                j = -j;
            }
        }

        let c = &a >> s; // a = 2^s*c

        // swap numerator and denominator
        if &b & BigInt::from(3) == BigInt::from(3) && &c & BigInt::from(3) == BigInt::from(3) {
            j = -j
        }

        a = b;
        b = c;
    }
}

fn is_bit_set(x: &BigUint, i: usize) -> bool {
    ((x >> i) & &*BIG_1) == *BIG_1
}

/// Generates biguint within `[0;upper)` range
fn gen_biguint_below<R: Rng>(r: &mut R, upper: &BigUint) -> BigUint {
    loop {
        let bits = upper.bits();
        let bytes = bits.div_ceil(8);
        let mut buf = vec![0u8; bytes as usize];
        r.fill_bytes(&mut buf);

        let mask = 0xff_u8 >> (bytes * 8 - bits);
        buf[0] &= mask;

        let n = BigUint::from_bytes_be(&buf);
        if &n < upper {
            break n;
        }
    }
}
