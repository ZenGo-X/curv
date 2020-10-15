pub trait Pairing<T1, T2, T3> {
    fn compute_pairing(element_1: &T1, element_2: &T2) -> T3;
}
