/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use merkle::{MerkleTree, Proof};
use ring::digest::{Context, SHA256};
use GE;
/*
pub struct MT256<'a> {
    tree: MerkleTree<GE>,
    root: & 'a Vec<u8>,
}
*/
pub struct MT256 {
    tree: MerkleTree<GE>,
}

//impl <'a> MT256<'a>{
impl MT256 {
    pub fn create_tree(vec: &[GE]) -> MT256 {
        let digest = Context::new(&SHA256);
        let tree = MerkleTree::from_vec(digest.algorithm, vec.to_vec());
        MT256 { tree }
    }

    pub fn gen_proof_for_ge(&self, value: &GE) -> Proof<GE> {
        MerkleTree::gen_proof(&self.tree, *value).expect("not found in tree")
    }

    pub fn get_root(&self) -> &Vec<u8> {
        MerkleTree::root_hash(&self.tree)
    }

    pub fn validate_proof(proof: &Proof<GE>, root: &[u8]) -> Result<(), ()> {
        if Proof::validate(proof, root) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::hashing::merkle_tree::MT256;
    use elliptic::curves::traits::ECPoint;
    use GE;
    #[test]
    fn test_mt_functionality_four_leaves() {
        let ge1: GE = ECPoint::generator();
        let ge2: GE = ECPoint::generator();
        let ge3: GE = ge1.add_point(&ge2.get_element());
        let ge4: GE = ge1.add_point(&ge3.get_element());
        let ge_vec = vec![ge1, ge2, ge3, ge4];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1: GE = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        let valid_proof = MT256::validate_proof(&proof1, root).is_ok();
        assert!(valid_proof);
    }

    #[test]
    fn test_mt_functionality_three_leaves() {
        let ge1: GE = ECPoint::generator();
        let ge2: GE = ECPoint::generator();
        let ge3: GE = ge1.add_point(&ge2.get_element());

        let ge_vec = vec![ge1, ge2, ge3];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1: GE = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        assert!(MT256::validate_proof(&proof1, root).is_ok());
    }
}
