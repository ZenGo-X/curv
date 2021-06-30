use std::fmt;

use derivative::Derivative;
use thiserror::Error;

use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::cryptographic_primitives::proofs::ProofError;
use crate::cryptographic_primitives::secret_sharing::Polynomial;
use crate::elliptic::curves::traits::ECPoint;

/// The prover private polynomial
#[derive(Derivative)]
#[derivative(Clone(bound = "P::Scalar: Clone"))]
#[derivative(Debug(bound = "P::Scalar: fmt::Debug"))]
pub struct LdeiWitness<P: ECPoint> {
    pub w: Polynomial<P>,
}

/// Claims that there's polynomial `w(x)` of degree `deg(w) <= degree`, and
/// `forall i. x[i] = g[i] * alpha[i]` (and the prover knows `w(x)`)
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Clone, P::Scalar: Clone"))]
#[derivative(Debug(bound = "P: fmt::Debug, P::Scalar: fmt::Debug"))]
pub struct LdeiStatement<P: ECPoint> {
    pub alpha: Vec<P::Scalar>,
    pub g: Vec<P>,
    pub x: Vec<P>,
    pub d: u16,
}

impl<P> LdeiStatement<P>
where
    P: ECPoint + Clone,
    P::Scalar: Clone + PartialEq,
{
    /// Takes [witness](LdeiWitness) (ie. secret polynomial `w(x)`), list of scalars `alpha`,
    /// list of generators `g`, number `d`. Produces LdeiStatement consisting of `alpha`, `g`, `d`,
    /// and list `x` such as `x_i = g_i * w(alpha_i)`
    pub fn new(
        witness: &LdeiWitness<P>,
        alpha: Vec<P::Scalar>,
        g: Vec<P>,
        d: u16,
    ) -> Result<Self, InvalidLdeiStatement> {
        if g.len() != alpha.len() {
            return Err(InvalidLdeiStatement::AlphaLengthDoesntMatchG);
        }
        if witness.w.degree() > d {
            return Err(InvalidLdeiStatement::PolynomialDegreeMoreThanD);
        }
        if !ensure_list_is_pairwise_distinct(&alpha) {
            return Err(InvalidLdeiStatement::AlphaNotPairwiseDistinct);
        }
        Ok(Self {
            x: g.iter()
                .zip(&alpha)
                .map(|(g, a)| g.clone() * witness.w.evaluate(a))
                .collect(),
            alpha,
            g,
            d,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P: Clone, P::Scalar: Clone"))]
#[derivative(Debug(bound = "P: fmt::Debug, P::Scalar: fmt::Debug"))]
pub struct LdeiProof<P: ECPoint> {
    pub a: Vec<P>,
    pub e: P::Scalar,
    pub z: Polynomial<P>,
}

impl<P> LdeiProof<P>
where
    P: ECPoint + Clone + PartialEq,
    P::Scalar: Clone + PartialEq,
{
    /// Constructs [LdeiStatement] and proves it correctness
    ///
    /// ## Protocol
    ///
    /// The prover samples `u(X) ← Z_q[X]` with `deg(u) ≤ d` and computes `a_i = g_i^u(alpha_i)`
    /// for all `i ∈ [m]`, in addition to `e = H(g_1,...,g_m,x_1,...,x_m,a_1,...,a_m)`, and
    /// `z(X) = u(X) − e · w(X)`. The proof is `(a_1,...,a_m,e,z)`.
    #[allow(clippy::many_single_char_names)]
    pub fn prove<H>(
        witness: &LdeiWitness<P>,
        statement: &LdeiStatement<P>,
    ) -> Result<LdeiProof<P>, InvalidLdeiStatement>
    where
        H: Hash,
    {
        if statement.alpha.len() != statement.g.len() {
            return Err(InvalidLdeiStatement::AlphaLengthDoesntMatchG);
        }
        if witness.w.degree() > statement.d {
            return Err(InvalidLdeiStatement::PolynomialDegreeMoreThanD);
        }
        if !ensure_list_is_pairwise_distinct(&statement.alpha) {
            return Err(InvalidLdeiStatement::AlphaNotPairwiseDistinct);
        }

        let x_expected: Vec<P> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .map(|(g, a)| g.clone() * witness.w.evaluate(a))
            .collect();
        if statement.x != x_expected {
            return Err(InvalidLdeiStatement::ListOfXDoesntMatchExpectedValue);
        }

        let u = Polynomial::<P>::sample(statement.d);
        let a: Vec<P> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .map(|(g, a)| g.clone() * u.evaluate(a))
            .collect();

        let hash_input: Vec<&P> = statement.g.iter().chain(&statement.x).chain(&a).collect();
        let e = H::create_hash_from_ge::<P>(hash_input.as_slice());

        let z = &u - &(&witness.w * &e);

        Ok(LdeiProof { a, e, z })
    }

    /// Verifies correctness of a statement
    ///
    /// ## Protocol
    ///
    /// The verifier checks that `e = H(g1,...,gm,x1,...,xm,a1,...,am)`, that
    /// `deg(z) ≤ d`, and that `a_i = g_i^z(αlpha_i) * x_i^e` for all i, and accepts if all of this is
    /// true, otherwise rejects.
    pub fn verify<H>(&self, statement: &LdeiStatement<P>) -> Result<(), ProofError>
    where
        H: Hash,
    {
        let hash_input: Vec<&P> = statement
            .g
            .iter()
            .chain(&statement.x)
            .chain(&self.a)
            .collect();
        let e = H::create_hash_from_ge::<P>(hash_input.as_slice());
        if e != self.e {
            return Err(ProofError);
        }
        if self.z.degree() > statement.d {
            return Err(ProofError);
        }

        let expected_a: Vec<_> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .zip(&statement.x)
            .map(|((g, a), x)| g.clone() * self.z.evaluate(&a) + x.clone() * e.clone())
            .collect();

        if self.a == expected_a {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

/// Indicates that statement is not valid or doesn't match a witness
#[derive(Debug, Error)]
pub enum InvalidLdeiStatement {
    #[error("`alpha`s are not pairwise distinct")]
    AlphaNotPairwiseDistinct,
    #[error("alpha.len() != g.len()")]
    AlphaLengthDoesntMatchG,
    #[error("deg(w) > d")]
    PolynomialDegreeMoreThanD,
    #[error("`statement.x` doesn't match expected value")]
    ListOfXDoesntMatchExpectedValue,
}

fn ensure_list_is_pairwise_distinct<S: PartialEq>(list: &[S]) -> bool {
    for (i, x1) in list.iter().enumerate() {
        for (j, x2) in list.iter().enumerate() {
            if i != j && x1 == x2 {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crate::arithmetic::BigInt;
    use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::test_for_all_curves;

    use super::*;

    test_for_all_curves!(correctly_proofs);
    fn correctly_proofs<P>()
    where
        P: ECPoint + Clone + PartialEq,
        P::Scalar: ECScalar + Clone + PartialEq,
    {
        let d = 5;
        let poly = Polynomial::<P>::sample_exact(5);
        let witness = LdeiWitness { w: poly };

        let alpha: Vec<P::Scalar> = (1..=10).map(|i| ECScalar::from(&BigInt::from(i))).collect();
        let g: Vec<P> = iter::repeat_with(ECScalar::new_random)
            .map(|x| P::generator() * x)
            .take(10)
            .collect();

        let statement = LdeiStatement::new(&witness, alpha, g, d).unwrap();

        let proof = LdeiProof::prove::<HSha256>(&witness, &statement).expect("failed to prove");
        proof
            .verify::<HSha256>(&statement)
            .expect("failed to validate proof");
    }
}
