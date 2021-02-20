#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_from {
    ($($type:ty),*$(,)?) => {
        $(
        impl From<$type> for BigInt {
            fn from(x: $type) -> Self {
                BN::from(x).wrap()
            }
        }
        )*
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_ops {
    () => {};
    ($op: ident $func:ident, $($rest:tt)*) => {
        impl ops::$op for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                self.inner_ref().$func(rhs.inner_ref()).wrap()
            }
        }
        impl ops::$op for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: Self) -> Self::Output {
                self.into_inner().$func(rhs.into_inner()).wrap()
            }
        }
        impl ops::$op<BigInt> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: BigInt) -> Self::Output {
                self.inner_ref().$func(rhs.into_inner()).wrap()
            }
        }
        impl ops::$op<&BigInt> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: &BigInt) -> Self::Output {
                self.into_inner().$func(rhs.inner_ref()).wrap()
            }
        }
        $crate::__bigint_impl_ops!{ $($rest)* }
    };
    ($op: ident $func:ident $primitive:ty, $($rest:tt)*) => {
        impl ops::$op<$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                self.into_inner().$func(rhs).wrap()
            }
        }
        impl ops::$op<$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                (&self.inner_ref()).$func(rhs).wrap()
            }
        }
        $crate::__bigint_impl_ops!{ $($rest)* }
    };
    ($op: ident $func:ident $primitive:ty [swap], $($rest:tt)*) => {
        impl ops::$op<$primitive> for BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                self.into_inner().$func(rhs).wrap()
            }
        }
        impl ops::$op<$primitive> for &BigInt {
            type Output = BigInt;
            fn $func(self, rhs: $primitive) -> Self::Output {
                (&self.inner_ref()).$func(rhs).wrap()
            }
        }
        impl ops::$op<BigInt> for $primitive {
            type Output = BigInt;
            fn $func(self, rhs: BigInt) -> Self::Output {
                self.$func(rhs.into_inner()).wrap()
            }
        }
        impl ops::$op<&BigInt> for $primitive {
            type Output = BigInt;
            fn $func(self, rhs: &BigInt) -> Self::Output {
                self.$func(rhs.inner_ref()).wrap()
            }
        }
        $crate::__bigint_impl_ops!{ $($rest)* }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __bigint_impl_assigns {
    () => {};
    ($trait:ident $fn:ident, $($rest:tt)*) => {
        impl ops::$trait for BigInt {
            fn $fn(&mut self, rhs: BigInt) {
                self.inner_mut().$fn(rhs.into_inner())
            }
        }
        impl ops::$trait<&BigInt> for BigInt {
            fn $fn(&mut self, rhs: &BigInt) {
                self.inner_mut().$fn(rhs.inner_ref())
            }
        }
        $crate::__bigint_impl_assigns!{ $($rest)* }
    };
    ($trait:ident $fn:ident $primitive:ident, $($rest:tt)*) => {
        impl ops::$trait<$primitive> for BigInt {
            fn $fn(&mut self, rhs: $primitive) {
                self.inner_mut().$fn(rhs)
            }
        }
        $crate::__bigint_impl_assigns!{ $($rest)* }
    };
}
