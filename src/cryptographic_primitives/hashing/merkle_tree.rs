/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/
use BigInt;
use merkle::{MerkleTree,Proof};
use {GE,FE};
use elliptic::curves::traits::{ECPoint,ECScalar};
use ring::digest::{Context, SHA256};
/*
pub struct MT256<'a> {
    tree: MerkleTree<GE>,
    root: & 'a Vec<u8>,
}
*/
pub struct MT256{
    tree: MerkleTree<GE>,

}

//impl <'a> MT256<'a>{
impl MT256{

    pub fn create_tree(vec: &Vec<GE>) -> MT256
    {
        let mut digest = Context::new(&SHA256);
        let tree= MerkleTree::from_vec(digest.algorithm, vec.to_vec());
        MT256{tree}

    }

    pub fn gen_proof_for_ge(&self, value: &GE) ->Proof<GE>{
        let proof = MerkleTree::gen_proof(&self.tree, value.clone()).expect("not found in tree");
        return proof;
    }

    pub fn get_root(&self) -> &Vec<u8>{
        MerkleTree::root_hash(&self.tree)
    }

    pub fn validate_proof(proof: &Proof<GE>, root: &Vec<u8>) -> Result<(),()>{
        if Proof::validate(proof, root) == true{
          Ok(())
        }
        else{
            Err(())
        }
    }

}

#[cfg(test)]
mod tests {
    use cryptographic_primitives::hashing::merkle_tree::MT256;
    use merkle::{MerkleTree,Proof};
    use {GE,FE};
    use ring::digest::{Context, SHA256};
    use elliptic::curves::traits::{ECPoint,ECScalar};
    #[test]
    fn test_mt_functionality_four_leaves() {
        let ge1 : GE = ECPoint::generator();
        let ge2 : GE = ECPoint::generator();
        let ge3 : GE = ge1.add_point(&ge2.get_element());
        let ge4 : GE = ge1.add_point(&ge3.get_element());
        let ge_vec = vec![ge1,ge2,ge3,ge4];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1 : GE = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        let valid_proof = MT256::validate_proof(&proof1, root).is_ok();
    }

    #[test]
    fn test_mt_functionality_three_leaves() {
        let ge1 : GE = ECPoint::generator();
        let ge2 : GE = ECPoint::generator();
        let ge3 : GE = ge1.add_point(&ge2.get_element());

        let ge_vec = vec![ge1,ge2,ge3];
        let mt256 = MT256::create_tree(&ge_vec);
        let ge1 : GE = ECPoint::generator();
        let proof1 = mt256.gen_proof_for_ge(&ge1);
        let root = mt256.get_root();
        let valid_proof = MT256::validate_proof(&proof1, root).is_ok();
    }

}
