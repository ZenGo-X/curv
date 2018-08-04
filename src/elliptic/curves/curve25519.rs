

use BigInt;

use arithmetic::traits::Converter;

use super::rand::thread_rng;

use super::curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use super::curve25519_dalek::constants::BASEPOINT_ORDER;
use super::curve25519_dalek::scalar::Scalar;
use super::curve25519_dalek::constants;
use super::curve25519_dalek::edwards::CompressedEdwardsY;
use super::curve25519_dalek::edwards::EdwardsPoint;
//use super::curve25519_dalek::field::FieldElement64;
use super::traits::{ECPoint, ECScalar};
pub const SECRET_KEY_SIZE: usize = 32;
pub const COOR_BYTE_SIZE: usize = 32;
pub const NUM_OF_COORDINATES: usize = 4;

/*

pub type SK = Scalar;
pub type PK = CompressedEdwardsY;

impl FieldElement<SK> {
    fn new_random(&self) -> SK {
        SK::random( &mut thread_rng())
    }

    fn from_big_int(&self,n: &BigInt) -> SK {
        let mut v = BigInt::to_vec(n);
        let mut bytes_array: [u8; SECRET_KEY_SIZE] = [0; SECRET_KEY_SIZE];
        let bytes = &v[..bytes_array.len()];
        bytes_array.copy_from_slice(&bytes);
        SK::from_bytes_mod_order(bytes_array)
    }

    fn to_big_int(&self) -> BigInt {
        BigInt::from(&self[0..self.len()])
    }

    fn get_q(&self) -> BigInt {
        BigInt::from(&BASEPOINT_ORDER[0..BASEPOINT_ORDER.len()].as_ref())
    }
}


impl ECPoint<PK,SK>{

    fn new() -> PK {
        constants::ED25519_BASEPOINT_COMPRESSED
    }

    fn get_x_coor_as_big_int(pubkey: &PK) -> BigInt{
        let field_x = PK::decompress(pubkey).unwrap().X;
        BigInt::from(&(field_x.to_bytes()))
    }

    fn get_y_coor_as_big_int(pubkey: &PK) -> BigInt{
        let field_y = PK::decompress(pubkey).unwrap().Y;
        BigInt::from(&(field_y.to_bytes()))
    }

    fn bytes_compressed_to_big_int(pubkey: &PK) -> BigInt{
        BigInt::from(&(pubkey.to_bytes()))


    }
    fn from_key_slice(key: &[u8]) -> PK{
        assert_eq!(key.len(), COOR_BYTE_SIZE*4);
        let mut array : [u8;32] = [0; 32];
        // first 32 elements (without the header)
       // let q1_end_index = COOR_BYTE_SIZE;
       // let q2_end_index = 2*COOR_BYTE_SIZE;
       // let q3_end_index = 3*COOR_BYTE_SIZE;
       // let q4_end_index = key.len();
       // array.copy_from_slice(&key[0..q1_end_index]);
       // let X  = FieldElement64::from_bytes(&array);
       // array.copy_from_slice(&key[q1_end_index..q2_end_index]);
       // let Y  = FieldElement64::from_bytes(&array);
       // array.copy_from_slice(&key[q2_end_index..q3_end_index]);
       // let Z = FieldElement64::from_bytes(&array);
       // array.copy_from_slice(&key[q3_end_index..q4_end_index]);
       // let T = FieldElement64::from_bytes(&array);
       // EdwardsPoint{X,Y,Z,T}.compress()
        array.copy_from_slice(key);
        CompressedEdwardsY(array)
        // TODO: add a test if point is on curve.

    }
    fn pk_to_key_slice(pubkey: &PK) -> Vec<u8>{
        let result = pubkey.to_bytes();
        result.to_vec()
    }
    fn scalar_mul(group_element: &PK, field_element: &SK) -> PK{
        //variable_base::mul(&(group_element.decompress().unwrap()),field_element).compress()
        field_element * group_element.decompress().unwrap()
    }
    fn add_point(group_element: &PK, other: &PK) -> PK{
        group_element + other

    }

}



*/

