use std::fmt;

use ff_zeroize::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use generic_array::GenericArray;
use pairing_plus::bls12_381::{Fr, FrRepr};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::arithmetic::*;
use crate::elliptic::curves::traits::*;

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = {
        let q_u64: [u64; 4] = [
            0xffffffff00000001,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ];
        let to_bn = q_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    };
}

const SECRET_KEY_SIZE: usize = 32;

pub type FE = FieldScalar;
pub type SK = <pairing_plus::bls12_381::Bls12 as ScalarEngine>::Fr;

#[derive(Clone)]
pub struct FieldScalar {
    purpose: &'static str,
    fe: Zeroizing<SK>,
}

impl ECScalar for FieldScalar {
    type Underlying = SK;

    type ScalarLength = typenum::U32;

    fn random() -> FieldScalar {
        FieldScalar {
            purpose: "random",
            fe: Zeroizing::new(Field::random(&mut OsRng)),
        }
    }

    fn zero() -> FieldScalar {
        FieldScalar {
            purpose: "zero",
            fe: Zeroizing::new(Field::zero()),
        }
    }

    fn from_bigint(n: &BigInt) -> FieldScalar {
        let bytes = n
            .modulus(Self::group_order())
            .to_bytes_array::<SECRET_KEY_SIZE>()
            .expect("n mod curve_order must be equal or less than 32 bytes");

        let mut repr = FrRepr::default();
        repr.read_be(bytes.as_ref()).unwrap();
        FieldScalar {
            purpose: "from_bigint",
            fe: Fr::from_repr(repr).unwrap().into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        let repr = self.fe.into_repr();
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        repr.write_be(&mut bytes[..]).unwrap();
        BigInt::from_bytes(&bytes)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        let repr = self.fe.into_repr();
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        repr.write_be(&mut bytes[..]).unwrap();
        GenericArray::from(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(DeserializationError);
        }
        let mut repr = FrRepr::default();
        repr.read_be(bytes.as_ref()).unwrap();
        Ok(FieldScalar {
            purpose: "deserialize",
            fe: Fr::from_repr(repr).or(Err(DeserializationError))?.into(),
        })
    }

    fn add(&self, other: &Self) -> FieldScalar {
        let mut result = self.fe.clone();
        result.add_assign(&other.fe);
        FieldScalar {
            purpose: "add",
            fe: result,
        }
    }

    fn mul(&self, other: &Self) -> FieldScalar {
        let mut result = self.fe.clone();
        result.mul_assign(&other.fe);
        FieldScalar {
            purpose: "mul",
            fe: result,
        }
    }

    fn sub(&self, other: &Self) -> FieldScalar {
        let mut result = self.fe.clone();
        result.sub_assign(&other.fe);
        FieldScalar {
            purpose: "sub",
            fe: result,
        }
    }

    fn neg(&self) -> FieldScalar {
        let mut result = self.fe.clone();
        result.negate();
        FieldScalar {
            purpose: "neg",
            fe: result,
        }
    }

    fn invert(&self) -> Option<FieldScalar> {
        Some(FieldScalar {
            purpose: "invert",
            fe: Zeroizing::new(self.fe.inverse()?),
        })
    }

    fn add_assign(&mut self, other: &Self) {
        self.fe.add_assign(&other.fe);
    }
    fn mul_assign(&mut self, other: &Self) {
        self.fe.mul_assign(&other.fe);
    }
    fn sub_assign(&mut self, other: &Self) {
        self.fe.sub_assign(&other.fe);
    }
    fn neg_assign(&mut self) {
        self.fe.negate();
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }
    fn from_underlying(fe: Self::Underlying) -> FieldScalar {
        FieldScalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl fmt::Debug for FieldScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose, self.fe,
        )
    }
}

impl PartialEq for FieldScalar {
    fn eq(&self, other: &FieldScalar) -> bool {
        self.fe == other.fe
    }
}
