use digest::Digest;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cryptographic_primitives::hashing::DigestExt;
use crate::cryptographic_primitives::proofs::ProofError;
use crate::cryptographic_primitives::secret_sharing::Polynomial;
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::HashChoice;

/// The prover private polynomial
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct LdeiWitness<E: Curve> {
    pub w: Polynomial<E>,
}

/// Claims that there's polynomial `w(x)` of degree `deg(w) <= degree`, and
/// `forall i. x[i] = g[i] * alpha[i]` (and the prover knows `w(x)`)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct LdeiStatement<E: Curve> {
    pub alpha: Vec<Scalar<E>>,
    pub g: Vec<Point<E>>,
    pub x: Vec<Point<E>>,
    pub d: u16,
}

impl<E: Curve> LdeiStatement<E> {
    /// Takes [witness](LdeiWitness) (ie. secret polynomial `w(x)`), list of scalars `alpha`,
    /// list of generators `g`, number `d`. Produces LdeiStatement consisting of `alpha`, `g`, `d`,
    /// and list `x` such as `x_i = g_i * w(alpha_i)`
    pub fn new(
        witness: &LdeiWitness<E>,
        alpha: Vec<Scalar<E>>,
        g: Vec<Point<E>>,
        d: u16,
    ) -> Result<Self, InvalidLdeiStatement> {
        if g.len() != alpha.len() {
            return Err(InvalidLdeiStatement::AlphaLengthDoesntMatchG);
        }
        if witness.w.degree() > d.into() {
            return Err(InvalidLdeiStatement::PolynomialDegreeMoreThanD);
        }
        if !ensure_list_is_pairwise_distinct(&alpha) {
            return Err(InvalidLdeiStatement::AlphaNotPairwiseDistinct);
        }
        Ok(Self {
            x: g.iter()
                .zip(&alpha)
                .map(|(g, a)| g * witness.w.evaluate(a))
                .collect(),
            alpha,
            g,
            d,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct LdeiProof<E: Curve, H: Digest + Clone> {
    pub a: Vec<Point<E>>,
    pub e: Scalar<E>,
    pub z: Polynomial<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> LdeiProof<E, H> {
    /// Proves correctness of [LdeiStatement]
    ///
    /// ## Protocol
    ///
    /// The prover samples `u(X) ← Z_q[X]` with `deg(u) ≤ d` and computes `a_i = g_i^u(alpha_i)`
    /// for all `i ∈ [m]`, in addition to `e = H(g_1,...,g_m,x_1,...,x_m,a_1,...,a_m)`, and
    /// `z(X) = u(X) − e · w(X)`. The proof is `(a_1,...,a_m,e,z)`.
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        witness: &LdeiWitness<E>,
        statement: &LdeiStatement<E>,
    ) -> Result<LdeiProof<E, H>, InvalidLdeiStatement> {
        if statement.alpha.len() != statement.g.len() {
            return Err(InvalidLdeiStatement::AlphaLengthDoesntMatchG);
        }
        if witness.w.degree() > statement.d.into() {
            return Err(InvalidLdeiStatement::PolynomialDegreeMoreThanD);
        }
        if !ensure_list_is_pairwise_distinct(&statement.alpha) {
            return Err(InvalidLdeiStatement::AlphaNotPairwiseDistinct);
        }

        let x_expected: Vec<Point<E>> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .map(|(g, a)| g * witness.w.evaluate(a))
            .collect();
        if statement.x != x_expected {
            return Err(InvalidLdeiStatement::ListOfXDoesntMatchExpectedValue);
        }

        let u = Polynomial::<E>::sample_exact(statement.d);
        let a: Vec<Point<E>> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .map(|(g, a)| g * u.evaluate(a))
            .collect();

        let e = H::new()
            .chain_points(&statement.g)
            .chain_points(&statement.x)
            .chain_points(&a)
            .result_scalar();

        let z = &u - &(&witness.w * &e);

        Ok(LdeiProof {
            a,
            e,
            z,
            hash_choice: HashChoice::new(),
        })
    }

    /// Verifies correctness of a statement
    ///
    /// ## Protocol
    ///
    /// The verifier checks that `e = H(g1,...,gm,x1,...,xm,a1,...,am)`, that
    /// `deg(z) ≤ d`, and that `a_i = g_i^z(αlpha_i) * x_i^e` for all i, and accepts if all of this is
    /// true, otherwise rejects.
    pub fn verify(&self, statement: &LdeiStatement<E>) -> Result<(), ProofError>
    where
        H: Digest + Clone,
    {
        let e = H::new()
            .chain_points(&statement.g)
            .chain_points(&statement.x)
            .chain_points(&self.a)
            .result_scalar();

        if e != self.e {
            return Err(ProofError);
        }
        if self.z.degree() > statement.d.into() {
            return Err(ProofError);
        }

        let expected_a: Vec<_> = statement
            .g
            .iter()
            .zip(&statement.alpha)
            .zip(&statement.x)
            .map(|((g, a), x)| g * self.z.evaluate(a) + x * &e)
            .collect();

        if self.a == expected_a {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

/// Indicates that statement is not valid or doesn't match a witness
#[derive(Debug, Clone, Error)]
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

    use crate::elliptic::curves::{Curve, Scalar};
    use crate::test_for_all_curves_and_hashes;

    use super::*;

    test_for_all_curves_and_hashes!(correctly_proofs);
    fn correctly_proofs<E: Curve, H: Digest + Clone>() {
        let d = 5;
        let poly = Polynomial::<E>::sample_exact(5);
        let witness = LdeiWitness { w: poly };

        let alpha: Vec<Scalar<E>> = (1..=10).map(Scalar::from).collect();
        let g: Vec<Point<E>> = iter::repeat_with(Scalar::random)
            .map(|x| Point::generator() * x)
            .take(10)
            .collect();

        let statement = LdeiStatement::new(&witness, alpha, g, d).unwrap();

        let proof = LdeiProof::<_, H>::prove(&witness, &statement).expect("failed to prove");
        proof.verify(&statement).expect("failed to validate proof");
    }
}
