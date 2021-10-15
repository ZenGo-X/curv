use crate::arithmetic::{Converter, Modulo};
use crate::BigInt;
use crate::{
    cryptographic_primitives::secret_sharing::Polynomial,
    elliptic::curves::{Scalar, Secp256k1},
};
use std::iter::Iterator;

/// Iterator for powers of a given element
///
/// For a given element $g$ and a non-negative number $c$, the iterator yields $g^0,g^1,\ldots,g^{c-1}$
struct PowerIterator {
    base: Scalar<Secp256k1>,
    next_pow: Scalar<Secp256k1>,
    next_idx: usize,
    max_idx: usize,
}

impl PowerIterator {
    pub fn new(base: Scalar<Secp256k1>, count: usize) -> Self {
        PowerIterator {
            base: base,
            next_pow: Scalar::<Secp256k1>::from(1),
            next_idx: 0,
            max_idx: count,
        }
    }
}
impl Iterator for PowerIterator {
    type Item = Scalar<Secp256k1>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next_idx == self.max_idx {
            return None;
        }
        let res = self.next_pow.clone();
        self.next_pow = &res * self.base.clone();
        self.next_idx += 1;
        Some(res)
    }
}
/// Iterator for all facorizations of a given number.
///
/// For a given number $s$ and its factorization $s=p_1^k_1 \cdot p_2^k_2 \cdot \ldots \cdot p_n^k_n$
/// this iterator yields all divisors of $s$.
struct FactorizationIterator<'a> {
    factorization: &'a [(usize, usize)],
    index: usize,
    max: usize,
}

// "115481771728459905245102424859900657047113141323743738905491223467302634970004" - of degree 18051648
// This is the biggest "small" factor of q-1.
const PRIMITIVE_ROOT_OF_UNITY: &str =
    "115481771728459905245102424859900657047113141323743738905491223467302634970004";
const ROOT_OF_UNITY_BASIC_ORDER: usize = 18051648;

// This is the factorization of [ROOT_OF_UNITY_BASIC_ORDER]
const FACTORIZATION_OF_ORDER: [(usize, usize); 4] = [(2, 6), (3, 1), (149, 1), (631, 1)];

impl<'a> FactorizationIterator<'a> {
    fn new(factors: &'a [(usize, usize)]) -> FactorizationIterator {
        let max = factors
            .iter()
            .fold(1usize, |acc, (_, count)| acc * (count + 1));
        return FactorizationIterator {
            factorization: factors,
            index: 0usize,
            max: max,
        };
    }
}

impl<'a> Iterator for FactorizationIterator<'a> {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        let mut max = self.max;
        if self.index >= max {
            return None;
        }
        #[allow(unused_parens)]
        let output = self
            .factorization
            .iter()
            .fold(1usize, |acc, (factor, count)| {
                let how_many = max % (count + 1);
                max /= (count + 1);
                acc * factor.pow(how_many as u32)
            });
        self.index += 1;
        Some(output)
    }
}

// Factors a number using a set of given factors
fn obtain_factorization(num: usize, factors: &[usize]) -> Option<Vec<(usize, usize)>> {
    let mut num_left = num;
    let ret_val = Some(
        factors
            .iter()
            .map(|factor| {
                let mut count = 0usize;
                while num_left % factor == 0 {
                    num_left /= factor;
                    count += 1;
                }
                (*factor, count)
            })
            .collect(),
    );
    if num_left != 1 {
        None
    } else {
        ret_val
    }
}

// Given a factorization of a number $n$ and a lower bar $b$, find the smallest $m$ such that $m|n$ and $m>b$
fn find_minimal_factorization_bigger_than<'a>(
    low_bar: usize,
    factorization: &'a [(usize, usize)],
) -> Option<Vec<(usize, usize)>> {
    let mut best_divisor = usize::MAX;
    for divisor in FactorizationIterator::new(factorization) {
        if divisor > low_bar && divisor < best_divisor {
            best_divisor = divisor;
        }
    }

    obtain_factorization(
        best_divisor,
        &factorization
            .iter()
            .map(|(factor, _)| *factor)
            .collect::<Vec<usize>>(),
    )
}

fn obtain_split_factor(factors: &Vec<(usize, usize)>, mut factor_index: usize) -> Option<usize> {
    for &(factor, count) in factors {
        if factor_index < count {
            return Some(factor);
        }
        factor_index -= count;
    }
    None
}

fn split_poylnomial(
    polynomial: Polynomial<Secp256k1>,
    factor: usize,
) -> Vec<Polynomial<Secp256k1>> {
    let mut coefficient_vectors = vec![Vec::new(); factor];
    polynomial
        .into_coefficients()
        .into_iter()
        .enumerate()
        .for_each(|(i, coefficient)| coefficient_vectors[i % factor].push(coefficient));
    coefficient_vectors
        .into_iter()
        .map(|coefficients| Polynomial::<Secp256k1>::from_coefficients(coefficients))
        .collect()
}

// Evaluates the polynomial on all the fft_size powers of the generator.
// Folds the recursion step with factor number factor_index from the size_factorization.
fn inverse_fft_internal(
    polynomial: Polynomial<Secp256k1>,
    generator: BigInt,
    size_factorization: &Vec<(usize, usize)>,
    fft_size: usize,
    factor_index: usize,
) -> Vec<Scalar<Secp256k1>> {
    let split_factor = obtain_split_factor(size_factorization, factor_index);
    let generator_scalar = Scalar::<Secp256k1>::from_bigint(&generator);
    match split_factor {
        None => PowerIterator::new(generator_scalar, fft_size)
            .into_iter()
            .map(|root| polynomial.evaluate(&root))
            .collect(),
        Some(split_factor) => {
            let post_split_generator = Scalar::<Secp256k1>::from_bigint(&BigInt::mod_pow(
                &generator,
                &BigInt::from(split_factor as u64),
                &(Scalar::<Secp256k1>::group_order() - 1),
            ));
            let split_polys = split_poylnomial(polynomial, split_factor);
            let evals: Vec<Vec<Scalar<Secp256k1>>> = split_polys
                .into_iter()
                .map(|sub_poly| {
                    inverse_fft_internal(
                        sub_poly,
                        post_split_generator.to_bigint(),
                        size_factorization,
                        fft_size / split_factor,
                        factor_index + 1,
                    )
                })
                .collect();
            PowerIterator::new(generator_scalar, fft_size)
                .into_iter()
                .enumerate()
                .map(|(idx, eval_item)| {
                    PowerIterator::new(eval_item, split_factor)
                        .into_iter()
                        .enumerate()
                        .map(|(degree, cur_item_degree)| {
                            cur_item_degree
                                * &evals[degree][((idx * split_factor) % fft_size) / split_factor]
                        })
                        .fold(Scalar::<Secp256k1>::zero(), |acc, cur| acc + cur)
                })
                .collect()
        }
    }
}

pub fn inverse_fft(polynomial: Polynomial<Secp256k1>) -> Vec<Scalar<Secp256k1>> {
    let polynomial_deg = polynomial.degree() as usize;
    let factors_to_expand =
        find_minimal_factorization_bigger_than(polynomial_deg as usize, &FACTORIZATION_OF_ORDER)
            .expect("Polynomial degree too big!");
    let fft_size = factors_to_expand
        .iter()
        .fold(1usize, |acc, &(factor, exponent)| {
            acc * factor.pow(exponent as u32) as usize
        });
    let fft_generator = BigInt::mod_pow(
        &BigInt::from_hex(PRIMITIVE_ROOT_OF_UNITY)
            .expect("Failed to decode primitive root of unitiy"),
        &BigInt::from((ROOT_OF_UNITY_BASIC_ORDER / fft_size) as u64),
        &(Scalar::<Secp256k1>::group_order() - 1),
    );
    inverse_fft_internal(polynomial, fft_generator, &factors_to_expand, fft_size, 0)
}

pub fn fft_internal(fft_vec: Vec<Scalar<Secp256k1>>) -> Polynomial<Scalar<Secp256k1> {
    // ---------------------------------------------------------------------------------
    // -------------------- Algorithm description in a nutshell (*) --------------------
    // ---------------------------------------------------------------------------------
    //  (*) - I really hope this will be a nutshell... let's see.
    //
    // So at this point we're looking for the coefficients of polynomial P(x) such that:
    //                  P(g^i) = fft_vec[i]
    // Where g is a root of unity of order of n=fft_vec.len().
    // The polynomial P(x) has the form:
    //                         n-1
    //                  P(x) = Sum a_ix^i
    //                         i=0
    // Let's say n has a small prime factor d.
    // i.e.: n=d*k for some integer k.
    // We can also write P(x) like this:
    //        d-1  k-1
    // P(x) = Sum {Sum a_{i+(j*d)}*x^{i+(j*d)}} =
    //        i=0  j=0
    // -------------------------------------------
    //        d-1      k-1
    //      = Sum {x^i Sum {a_{i+(j*d)}*x^{j*d}}}
    //        i=0      j=0
    //                                k-1
    // For each i we can denote each  Sum {a_{i+j*d} * x^{j*d}} as a polynomial P_i(x).
    //                                j=0
    //                            k-1
    // We can also write P_i(x) = Sum {a_{i+j*d} * (x^d)*j}.
    //                            j=0
    // By making the substitution y=x^d we can think of P_i(y) as the following:
    //          k-1
    // P_i(y) = Sum {a_{i+j*d} * y^j} which is a polynomial of degree k.
    //          j=0
    //
    // Coroallary #1:
    // Had we known the coefficients of all P_i(y) we could very simply derive the
    // coefficients of P(x) = sum a_ix^i, since each coefficient of each P_i(y) is
    // algebraically equal to a coefficient of P(x).
    //
    // Recall we have fft_vec, a vector of evaluations of P(x) on a set of powers of
    // a primitive root-of-unity of order n.
    // From those, we can derive the evaluation of P_i(x) for the powers of a
    // root-of-unity of order n/d.
    //
    // Let g denote the primitive root of unity of order n.
    // Let h=g^d, be the primitive root of unity of order n/d.
    // Let h^i for some 0<=i<n/d be a power of h.
    // Thus, there are d powers of g: g^{i_1},...,g^{i_d} such that
    // (g^{i_1})^d = ... = g^{i_d}^d = h^i.
    // Thus the following equations hold:
    // Consider the following set of d equations:
    //
    // - P(g^{i_1}) = P_0(h) + g^{i_1}*P_1(h) + ... + (g^{i_1})^{d-1})*P_{d-1}(h)
    // - P(g^{i_2}) = P_0(h) + g^{i_2}*P_1(h) + ... + (g^{i_2})^{d-1})*P_{d-1}(h)
    //   ........................................................................
    // - P(g^{i_d}) = P_0(h) + g^{i_d}*P_1(h) + ... + (g^{i_d})^{d-1})*P_{d-1}(h)
    //
    // This set of equations can also be written using matrix/vector notation:
    // (P(g^{i_1}))      (1  g^{i_1}   (g^{i_1})^2 .... (g^{i_1})^{d-1})   (  P_0(h^i)  )
    // (P(g^{i_2}))      (1  g^{i_2}   (g^{i_2})^2 .... (g^{i_2})^{d-1})   (  P_1(h^i)  )
    // (..........) ==== (.............................................) X (............)
    // (..........)      (.............................................)   (............)
    // (P(g^{i_d}))      (1  g^{i_d}   (g^{i_d})^2 .... (g^{i_d})^{d-1})   (P_{d-1}(h^i))
    // \____ ____/       \_______________________  ___________________/    \_____ ____/
    //      V                                    v                               v
    //      A                                    B                               C
    //
    // We know vector A (since the evaluations are given in fft_vec).
    // We can invert B (it's a vandermonde's matrix).
    // So we can compute C = B^{-1} * A
    // By doing so for h^i for all 0<=i<n/d we can obtain the evaluations of
    // P_0,...,P_{d-1} of degree n/d over n/d powers of primitive root of unity h
    // So we can recusively obtain the coefficient-representation of P_0,...,P_{d-1}.
    // From those representations we can obtain the coefficient-representation of P(x)
    // (based on Corollary #1).


}
// evaluations[i] = P(g^i)
pub fn fft(evaluations: Vec<Scalar<Secp256k1>>) -> Polynomial<Scalar<Secp256k1>> {
    // Find the factorization of the length of the evaluation vector.
    let factorization = obtain_factorization(evaluations.len(), &FACTORIZATION_OF_ORDER).expect(
        "The size of the given FFT doesn't divide the order of the primitive-root-of-unity.",
    );

    // Start folding.
}
