/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

// enabled via feature since it uses rust-crypto.

use std::marker::PhantomData;

use crypto::sha3::Sha3;
use merkle::{MerkleTree, Proof};

use crate::elliptic::curves::{Curve, Point};
/*
pub struct MT256<'a> {
    tree: MerkleTree<GE>,
    root: & 'a Vec<u8>,
}
*/
pub struct MT256<E: Curve> {
    tree: MerkleTree<[u8; 32]>,
    _ph: PhantomData<E>,
}

//impl <'a> MT256<'a>{
impl<E: Curve> MT256<E> {
    pub fn create_tree(vec: &[Point<E>]) -> MT256<E> {
        let digest = Sha3::keccak256();
        let vec_bytes = (0..vec.len())
            .map(|i| {
                let mut array = [0u8; 32];
                let bytes = vec[i]
                    .to_bytes(false)
                    .unwrap_or_else(|| b"infinity point".to_vec());
                array.copy_from_slice(&bytes[0..32]);
                array
            })
            .collect::<Vec<[u8; 32]>>();
        let tree = MerkleTree::from_vec::<[u8; 32]>(digest, vec_bytes);

        MT256 {
            tree,
            _ph: PhantomData,
        }
    }

    pub fn gen_proof_for_ge(&self, value: &Point<E>) -> Proof<[u8; 32]> {
        let mut array = [0u8; 32];
        let pk_slice = value
            .to_bytes(false)
            .unwrap_or_else(|| b"infinity point".to_vec());
        array.copy_from_slice(&pk_slice[0..32]);
        MerkleTree::gen_proof::<[u8; 32]>(&self.tree, array).expect("not found in tree")
    }

    pub fn get_root(&self) -> &Vec<u8> {
        MerkleTree::root_hash(&self.tree)
    }

    #[allow(clippy::result_unit_err)]
    pub fn validate_proof(proof: &Proof<[u8; 32]>, root: &[u8]) -> Result<(), ()> {
        if Proof::validate::<[u8; 32]>(proof, root) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MT256;
    use crate::elliptic::curves::{Curve, Point};

    use crate::test_for_all_curves;

    test_for_all_curves!(test_mt_functionality_four_leaves);

    fn test_mt_functionality_four_leaves<E: Curve>() {
        let ge1: Point<E> = Point::generator().to_point().into();
        let ge2: Point<E> = ge1.clone();
        let ge3: Point<E> = &ge1 + &ge2;
        let ge4: Point<E> = &ge1 + &ge3;
        let ge_vec = vec![ge1.clone(), ge2, ge3, ge4];
        let mt256 = MT256::create_tree(&ge_vec);
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        let valid_proof = MT256::<E>::validate_proof(&proof1, root).is_ok();
        assert!(valid_proof);
    }

    test_for_all_curves!(test_mt_functionality_three_leaves);

    fn test_mt_functionality_three_leaves<E: Curve>() {
        let ge1: Point<E> = Point::generator().to_point().into();
        let ge2: Point<E> = ge1.clone();
        let ge3: Point<E> = &ge1 + &ge2;

        let ge_vec = vec![ge1.clone(), ge2, ge3];
        let mt256 = MT256::create_tree(&ge_vec);
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        assert!(MT256::<E>::validate_proof(&proof1, root).is_ok());
    }
}
