/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use std::marker::PhantomData;

use digest::{Digest, Output};
use merkle_cbt::merkle_tree::{Merge, MerkleProof, MerkleTree, CBMT};
use serde::{Deserialize, Serialize};

use crate::cryptographic_primitives::hashing::DigestExt;
use crate::cryptographic_primitives::proofs::ProofError;
use crate::elliptic::curves::{Curve, Point};

pub struct MT256<E: Curve, H: Digest> {
    tree: MerkleTree<Output<H>, MergeDigest<H>>,
    leaves: Vec<Point<E>>,
}

impl<E: Curve, H: Digest + Clone> MT256<E, H> {
    pub fn create_tree(leaves: Vec<Point<E>>) -> Self {
        let hashes = leaves
            .iter()
            .map(|leaf| H::new().chain_point(leaf).finalize())
            .collect::<Vec<_>>();

        MT256 {
            tree: CBMT::<Output<H>, MergeDigest<H>>::build_merkle_tree(&hashes),
            leaves,
        }
    }

    pub fn build_proof(&self, point: Point<E>) -> Option<Proof<E, H>> {
        let index = (0u32..)
            .zip(&self.leaves)
            .find(|(_, leaf)| **leaf == point)
            .map(|(i, _)| i)?;
        let proof = self.tree.build_proof(&[index])?;
        Some(Proof {
            index: proof.indices()[0],
            lemmas: proof.lemmas().to_vec(),
            point,
        })
    }

    pub fn get_root(&self) -> Output<H> {
        self.tree.root()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Output<H>: Serialize",
    deserialize = "Output<H>: Deserialize<'de>"
))]
pub struct Proof<E: Curve, H: Digest> {
    pub index: u32,
    pub lemmas: Vec<Output<H>>,
    pub point: Point<E>,
}

impl<E: Curve, H: Digest + Clone> Proof<E, H> {
    pub fn verify(&self, root: &Output<H>) -> Result<(), ProofError> {
        let leaf = H::new().chain_point(&self.point).finalize();
        let valid =
            MerkleProof::<Output<H>, MergeDigest<H>>::new(vec![self.index], self.lemmas.clone())
                .verify(root, &[leaf]);
        if valid {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

struct MergeDigest<D>(PhantomData<D>);

impl<D> Merge for MergeDigest<D>
where
    D: Digest,
{
    type Item = Output<D>;

    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        D::new().chain(left).chain(right).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::MT256;
    use crate::elliptic::curves::{Curve, Point};

    use crate::test_for_all_curves;

    test_for_all_curves!(test_mt_functionality_four_leaves);

    fn test_mt_functionality_four_leaves<E: Curve>() {
        let ge1: Point<E> = Point::generator().to_point();
        let ge2: Point<E> = ge1.clone();
        let ge3: Point<E> = &ge1 + &ge2;
        let ge4: Point<E> = &ge1 + &ge3;
        let ge_vec = vec![ge1.clone(), ge2, ge3, ge4];
        let mt256 = MT256::<_, sha3::Keccak256>::create_tree(ge_vec);
        let proof1 = mt256.build_proof(ge1).unwrap();
        let root = mt256.get_root();
        proof1.verify(&root).expect("proof is invalid");
    }

    test_for_all_curves!(test_mt_functionality_three_leaves);

    fn test_mt_functionality_three_leaves<E: Curve>() {
        let ge1: Point<E> = Point::generator().to_point();
        let ge2: Point<E> = ge1.clone();
        let ge3: Point<E> = &ge1 + &ge2;

        let ge_vec = vec![ge1.clone(), ge2, ge3];
        let mt256 = MT256::<_, sha3::Keccak256>::create_tree(ge_vec);
        let proof1 = mt256.build_proof(ge1).unwrap();
        let root = mt256.get_root();
        proof1.verify(&root).expect("proof is invalid");
    }
}
