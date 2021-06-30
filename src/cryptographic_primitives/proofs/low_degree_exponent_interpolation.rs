use std::fmt;

use derivative::Derivative;
use thiserror::Error;

use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::cryptographic_primitives::proofs::ProofError;
use crate::cryptographic_primitives::Polynomial;
use crate::elliptic::curves::traits::ECPoint;

/// Claims that there's polynomial `w(x)` of degree `deg(w) <= degree`, and
/// `forall i. x[i] = g[i] * alpha[i]` (and the prover knows `w(x)`)
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Clone, P::Scalar: Clone"))]
#[derivative(Debug(bound = "P: fmt::Debug, P::Scalar: fmt::Debug"))]
pub struct LdeiStatement<P: ECPoint> {
    pub alpha: Vec<P::Scalar>,
    pub g: Vec<P>,
    pub x: Vec<P>,
    pub degree: u16,
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
        w: &Polynomial<P>,
        alpha: Vec<P::Scalar>,
        g: Vec<P>,
    ) -> Result<(LdeiStatement<P>, LdeiProof<P>), LdeiProofError>
    where
        H: Hash,
    {
        if alpha.len() != g.len() {
            return Err(LdeiProofError::AlphaLengthDoesntMatchG);
        }

        // Check that alphas are pairwise distinct
        for (i, a1) in alpha.iter().enumerate() {
            for (j, a2) in alpha.iter().enumerate() {
                if i != j && a1 == a2 {
                    return Err(LdeiProofError::AlphaNotPairwiseDistinct);
                }
            }
        }

        let x: Vec<P> = g
            .iter()
            .zip(&alpha)
            .map(|(g, a)| g.clone() * w.evaluate(a))
            .collect();

        let d = w.degree();
        let u = Polynomial::<P>::sample(d);
        let a: Vec<P> = g
            .iter()
            .zip(&alpha)
            .map(|(g, a)| g.clone() * u.evaluate(a))
            .collect();

        let hash_input: Vec<&P> = g.iter().chain(&x).chain(&a).collect();
        let e = H::create_hash_from_ge::<P>(hash_input.as_slice());

        let z = &u - &(w * &e);

        let statement = LdeiStatement {
            alpha,
            g,
            x,
            degree: d,
        };
        let proof = LdeiProof { a, e, z };

        Ok((statement, proof))
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
        if self.z.degree() > statement.degree {
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

#[derive(Debug, Error)]
pub enum LdeiProofError {
    #[error("`alpha`s are not pairwise distinct")]
    AlphaNotPairwiseDistinct,
    #[error("alpha.len() != g.len()")]
    AlphaLengthDoesntMatchG,
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
        let poly = Polynomial::<P>::sample_exact(5);

        let alpha: Vec<P::Scalar> = (1..=10).map(|i| ECScalar::from(&BigInt::from(i))).collect();
        let g: Vec<P> = iter::repeat_with(ECScalar::new_random)
            .map(|x| P::generator() * x)
            .take(10)
            .collect();

        let (statement, proof) =
            LdeiProof::prove::<HSha256>(&poly, alpha, g).expect("failed to prove");
        proof
            .verify::<HSha256>(&statement)
            .expect("failed to validate proof");
    }

    test_for_all_curves!(catches_invalid_args);
    fn catches_invalid_args<P>()
    where
        P: ECPoint + Clone + PartialEq + fmt::Debug,
        P::Scalar: ECScalar + Clone + PartialEq + fmt::Debug,
    {
        let poly = Polynomial::<P>::sample_exact(5);

        // Test that prove requires alphas.len() == g.len()
        {
            let alpha: Vec<P::Scalar> =
                (2..=10).map(|i| ECScalar::from(&BigInt::from(i))).collect();
            let g: Vec<P> = iter::repeat_with(ECScalar::new_random)
                .map(|x| P::generator() * x)
                .take(10)
                .collect();
            let result = LdeiProof::prove::<HSha256>(&poly, alpha, g);
            if !matches!(result, Err(LdeiProofError::AlphaLengthDoesntMatchG)) {
                panic!("Unexpected result: {:?}", result);
            }
        }

        // Test that prove requires alphas to be pairwise distinct
        {
            let alpha: Vec<P::Scalar> = iter::once(2)
                .chain(2..=10)
                .map(|i| ECScalar::from(&BigInt::from(i)))
                .collect();
            let g: Vec<P> = iter::repeat_with(ECScalar::new_random)
                .map(|x| P::generator() * x)
                .take(10)
                .collect();
            let result = LdeiProof::prove::<HSha256>(&poly, alpha, g);
            if !matches!(result, Err(LdeiProofError::AlphaNotPairwiseDistinct)) {
                panic!("Unexpected result: {:?}", result);
            }
        }
    }
}
