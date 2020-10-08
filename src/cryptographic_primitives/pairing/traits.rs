use crate::g2_instance;
use crate::bls12_381_instance;
use crate::

pub trait Pairing{
    fn compute_pairing(element_1:bls12_381,element_2:g2);
}