use super::pairing_bls12_381::PairingBls;
use super::pairing_bls12_381::PAIRING;
use crate::elliptic::curves::bls12_381::g1;
use crate::elliptic::curves::bls12_381::g2;
use crate::BigInt;
use crate::cryptographic_primitives::hashing::hash_sha256;
use crate::cryptographic_primitives::hashing::traits::Hash;
use crate::elliptic::curves::traits::ECPoint;
use crate::elliptic::curves::traits::ECScalar;
use serde::export::fmt::Debug;


type GE1 = g1::GE;
type GE2 = g2::GE;



pub fn hash_to_curve<P>(message: &BigInt) -> P
    where P: ECPoint + Clone + Debug
{
    let hashed = hash_sha256::HSha256::create_hash(&[message]);
    let hashed_scalar = <P::Scalar as ECScalar>::from(&hashed);
    P::generator().scalar_mul(&hashed_scalar.get_element())
}

#[derive(Clone,Copy,Debug)]
pub struct KeyPair<P: ECPoint>{
    sk: P::Scalar,
    pk: P
}


impl<P> KeyPair<P>
    where P: ECPoint + Clone + Debug
    {
    pub fn create_pair() -> Self
        {
            let sk = P::Scalar::new_random();
            let pk: P = P::generator().scalar_mul(&sk.get_element());
            Self{ sk, pk }
        }

    pub fn compute_signature(self, message: &BigInt) -> P::Scalar {
        let sk = self.sk;
        let signature = sk.mul(&<P::Scalar as ECScalar>::from(message).get_element());
        signature
    }

    /*
    pub fn compute_public_term<P>(self, message: &BigInt) -> P
        where P: ECPoint + Clone + Debug
    {
        let hashed = hash_sha256::HSha256::create_hash(&[&message, &BigInt::from(1)]);
        let hashed_scalar = ECScalar::from(&hashed);

        let pk:ECPoint = self.pk;
         pk.scalar_mul(&hashed_scalar);
    }
*/


}

pub fn verify_bls_signature(key_pair:&KeyPair<GE2>, message: &BigInt) -> bool {
    let left_side= PairingBls::compute_pairing(&hash_to_curve::<GE1>(message), &key_pair.pk );
    let signature_point = GE1::generator().scalar_mul(&key_pair.compute_signature(message).get_element());
    let right_side = PairingBls::compute_pairing( &signature_point,&GE2::generator());
    left_side == right_side
}


mod test{
    #[allow(unused_imports)]
    use super::*;


    #[test]
    pub fn test_simple_bls(){
        let key_pair: KeyPair<GE2> = KeyPair::create_pair();
        let message: [u8; 4] = [79, 77, 69, 82];
        let check = verify_bls_signature(
            &key_pair,&hash_sha256::HSha256::create_hash_from_slice(&message)
        );
        assert!(check);
    }
}