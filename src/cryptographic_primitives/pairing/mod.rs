pub mod pairing_bls12_381;
pub mod traits;
mod bls;

pub struct Signature{
    public_key: GE,
    private_key: FE,
    signature: GE
}

impl Signature{
    pub fn generate_key()-> FE{
        FE::<ECScalar<>>::new_random()
    }
}