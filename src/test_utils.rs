#[cfg(test)]
#[macro_export]
macro_rules! test_for_all_curves {
    (#[should_panic] $fn: ident) => {
        crate::test_for_all_curves!([#[should_panic]] $fn);
    };
    ($fn: ident) => {
        crate::test_for_all_curves!([] $fn);
    };
    ([$($attrs:tt)*] $fn: ident) => {
        crate::test_for_all!{[$($attrs)*] $fn =>
            secp256k1 = crate::elliptic::curves::Secp256k1,
            p256 = crate::elliptic::curves::Secp256r1,
            ed25519 = crate::elliptic::curves::Ed25519,
            ristretto = crate::elliptic::curves::Ristretto,
            bls12_381_1 = crate::elliptic::curves::Bls12_381_1,
            bls12_381_2 = crate::elliptic::curves::Bls12_381_2,
        }
    };
}

#[cfg(test)]
#[macro_export]
macro_rules! test_for_all_hashes {
    (#[should_panic] $fn: ident) => {
        crate::test_for_all_hashes!([#[should_panic]] $fn);
    };
    ($fn: ident) => {
        crate::test_for_all_hashes!([] $fn);
    };
    ([$($attrs:tt)*] $fn: ident) => {
        crate::test_for_all!{[$($attrs)*] $fn =>
            sha256 = sha2::Sha256,
            sha512 = sha2::Sha512,
            sha3_256 = sha3::Sha3_256,
            sha3_512 = sha3::Sha3_512,
            blake2b = blake2::Blake2b,
            blake2s = blake2::Blake2s,
        }
    };
}

#[cfg(test)]
#[macro_export]
macro_rules! test_for_all {
    ([$($attrs:tt)*] $fn: ident =>) => {};
    ([$($attrs:tt)*] $fn: ident => $inst_name: ident = $inst:path, $($rest: tt)*) => {
        paste::paste!{
            #[test]
            $($attrs)*
            fn [<$fn _$inst_name>]() {
                $fn::<$inst>()
            }
        }
        crate::test_for_all!([$($attrs)*] $fn => $($rest)*);
    };
}

#[cfg(test)]
#[macro_export]
macro_rules! test_for_all_curves_and_hashes {
    (#[should_panic] $fn: ident) => {
        crate::test_for_all_curves_and_hashes!([#[should_panic]] $fn);
    };
    ($fn: ident) => {
        crate::test_for_all_curves_and_hashes!([] $fn);
    };
    ([$($attrs:tt)*] $fn: ident) => {
        crate::test_for_all_curves_and_hashes!{compose: [$($attrs)*] $fn =>
            secp256k1 = crate::elliptic::curves::Secp256k1,
            p256 = crate::elliptic::curves::Secp256r1,
            ed25519 = crate::elliptic::curves::Ed25519,
            ristretto = crate::elliptic::curves::Ristretto,
            bls12_381_1 = crate::elliptic::curves::Bls12_381_1,
            bls12_381_2 = crate::elliptic::curves::Bls12_381_2,
        }
    };
    (compose: [$($attrs:tt)*] $fn: ident =>) => {};
    (compose: [$($attrs:tt)*] $fn: ident => $inst_name: ident = $inst:path, $($rest: tt)*) => {
        crate::test_for_all_curves_and_hashes!{private: [$($attrs)*] $fn =>
            $inst_name = $inst | sha256 = sha2::Sha256,
            $inst_name = $inst | sha512 = sha2::Sha512,
        }
        crate::test_for_all_curves_and_hashes!(compose: [$($attrs)*] $fn => $($rest)*);
    };
    (private: [$($attrs:tt)*] $fn: ident =>) => {};
    (private: [$($attrs:tt)*] $fn:ident => $inst_name1:ident = $inst1: path | $inst_name2:ident = $inst2:path, $($rest: tt)*) => {
        paste::paste!{
            #[test]
            $($attrs)*
            fn [<$fn _$inst_name1 _$inst_name2>]() {
                $fn::<$inst1, $inst2>()
            }
        }
        crate::test_for_all_curves_and_hashes!(private: [$($attrs)*] $fn => $($rest)*);
    };
}
