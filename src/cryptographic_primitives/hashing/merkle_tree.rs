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

use crate::elliptic::curves::traits::ECPoint;
/*
pub struct MT256<'a> {
    tree: MerkleTree<GE>,
    root: & 'a Vec<u8>,
}
*/
pub struct MT256<P> {
    tree: MerkleTree<[u8; 32]>,
    _ph: PhantomData<P>,
}

//impl <'a> MT256<'a>{
impl<P: ECPoint> MT256<P> {
    pub fn create_tree(vec: &[P]) -> MT256<P> {
        let digest = Sha3::keccak256();
        let mut array = [0u8; 32];
        let vec_bytes = (0..vec.len())
            .map(|i| {
                let bytes = vec[i].pk_to_key_slice();
                array.copy_from_slice(&bytes[0..32]);
                array
            })
            .collect::<Vec<[u8; 32]>>();
        let tree = MerkleTree::from_vec::<[u8; 32]>(digest, vec_bytes);

        MT256 { tree, _ph: PhantomData }
    }

    pub fn gen_proof_for_ge(&self, value: &P) -> Proof<[u8; 32]> {
        let mut array = [0u8; 32];
        let pk_slice = value.pk_to_key_slice();
        array.copy_from_slice(&pk_slice[0..32]);
        MerkleTree::gen_proof::<[u8; 32]>(&self.tree, array).expect("not found in tree")
    }

    pub fn get_root(&self) -> &Vec<u8> {
        MerkleTree::root_hash(&self.tree)
    }

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
    use crate::elliptic::curves::traits::ECPoint;
    use super::MT256;

    use crate::test_for_all_curves;

    test_for_all_curves!(test_mt_functionality_four_leaves);

    fn test_mt_functionality_four_leaves<P: ECPoint>() {
        let ge1: P = ECPoint::generator();
        let ge2: P = ECPoint::generator();
        let ge3: P = ge1.add_point(&ge2.get_element());
        let ge4: P = ge1.add_point(&ge3.get_element());
        let ge_vec = vec![ge1, ge2, ge3, ge4];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1: P = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        let valid_proof = MT256::<P>::validate_proof(&proof1, root).is_ok();
        assert!(valid_proof);
    }

    test_for_all_curves!(test_mt_functionality_three_leaves);

    fn test_mt_functionality_three_leaves<P: ECPoint>() {
        let ge1: P = ECPoint::generator();
        let ge2: P = ECPoint::generator();
        let ge3: P = ge1.add_point(&ge2.get_element());

        let ge_vec = vec![ge1, ge2, ge3];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1: P = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        assert!(MT256::<P>::validate_proof(&proof1, root).is_ok());
    }
}
