#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_ops {
    ($($op: ident $func:ident),+$(,)?) => {
        $(
        impl ops::$op for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                BigInt((&self.0).$func(&rhs.0))
            }
        }
        impl ops::$op for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                BigInt(self.0.$func(rhs.0))
            }
        }
        impl ops::$op<BigInt> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: BigInt) -> Self::Output {
                BigInt((&self.0).$func(rhs.0))
            }
        }
        impl ops::$op<&BigInt> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: &BigInt) -> Self::Output {
                BigInt(self.0.$func(&rhs.0))
            }
        }
        )+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_primitives_ops {
    () => {};
    ($op: ident $func:ident $primitive:ty, $($rest:tt)*) => {
        impl ops::$op<$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                BigInt(self.0.$func(rhs))
            }
        }
        impl ops::$op<$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
               BigInt((&self.0).$func(rhs))
            }
        }
        $crate::__bigint_impl_primitives_ops!($($rest)*);
    };
    (swap => $op: ident $func:ident $primitive:ty, $($rest:tt)*) => {
            impl ops::$op<$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                BigInt(self.0.$func(rhs))
            }
        }
        impl ops::$op<$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
               BigInt((&self.0).$func(rhs))
            }
        }
        impl ops::$op<&$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: &$primitive) -> Self::Output {
                BigInt(self.0.$func(rhs))
            }
        }
        impl ops::$op<&$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: &$primitive) -> Self::Output {
               BigInt((&self.0).$func(rhs))
            }
        }
        impl ops::$op<BigInt> for $primitive {
            type Output = BigInt;
            fn $func(self, rhs: BigInt) -> Self::Output {
                BigInt(self.$func(rhs.0))
            }
        }
        impl ops::$op<&BigInt> for $primitive {
            type Output = BigInt;
            fn $func(self, rhs: &BigInt) -> Self::Output {
                BigInt(self.$func(&rhs.0))
            }
        }
        $crate::__bigint_impl_primitives_ops!($($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_all_primitives_ops {
    () => {};
    ($op: ident $func:ident, $($rest:tt)*) => {
        $crate::__bigint_impl_primitives_ops!(
            $op $func u8,
            $op $func i8,
            $op $func u16,
            $op $func i16,
            $op $func u32,
            $op $func i32,
            $op $func u64,
            $op $func i64,
            $op $func u128,
            $op $func i128,
        );
        $crate::__bigint_impl_all_primitives_ops!{ $($rest)* }
    };
    (swap => $op: ident $func:ident, $($rest:tt)*) => {
            $crate::__bigint_impl_primitives_ops!(
            swap => $op $func u8,
            swap => $op $func i8,
            swap => $op $func u16,
            swap => $op $func i16,
            swap => $op $func u32,
            swap => $op $func i32,
            swap => $op $func u64,
            swap => $op $func i64,
            swap => $op $func u128,
            swap => $op $func i128,
        );
            $crate::__bigint_impl_all_primitives_ops!{ $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_assigns {
    () => {};
    ($trait: ident $fn:ident, $($rest:tt)*) => {
        impl ops::$trait for BigInt {
            fn $fn(&mut self, rhs: BigInt) {
                self.0.$fn(rhs.0)
            }
        }
        impl ops::$trait<&BigInt> for BigInt {
            fn $fn(&mut self, rhs: &BigInt) {
                self.0.$fn(&rhs.0)
            }
        }
        $crate::__bigint_impl_assigns!{ $($rest)* }
    };
    ($trait:ident $fn:ident $primitive:ident, $($rest:tt)*) => {
        impl ops::$trait<$primitive> for BigInt {
            fn $fn(&mut self, rhs: $primitive) {
                self.0.$fn(rhs)
            }
        }
        $crate::__bigint_impl_assigns!{ $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_fmt {
    ($(impl $trait:ident for $type:ty),+$(,)?) => {
        $(
        impl core::fmt::$trait for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                core::fmt::$trait::fmt(&self.0, f) // delegate to inner
            }
        }
        )+
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_from {
    ($($scalar:ty => $trait:ident => $func:ident),+$(,)?) => {
        $(
        impl $trait<$scalar> for BigInt {
            fn $func(input: $scalar) -> Self {
                BigInt($trait::$func(input))
            }
        }
        impl $trait<&$scalar> for BigInt {
            fn $func(input: &$scalar) -> Self {
                BigInt($trait::$func(*input))
            }
        }
        )+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_cmp {
    () => {};
    (impl $rhs:ident with $transform:path, $($rest:tt)*) => {
        impl PartialOrd<$rhs> for BigInt {
            fn partial_cmp(&self, other: &$rhs) -> Option<cmp::Ordering> {
                Some(self.cmp(&$transform(*other)))
            }
        }

        impl PartialEq<$rhs> for BigInt {
            fn eq(&self, other: &$rhs) -> bool {
                *self == $transform(*other)
            }
        }
        $crate::__bigint_impl_cmp!{ $($rest)* }
    };
}
