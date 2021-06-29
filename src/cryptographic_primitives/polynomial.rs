use std::convert::TryFrom;
use std::{fmt, iter, ops};

use derivative::Derivative;

use crate::elliptic::curves::traits::{ECPoint, ECScalar};
use crate::BigInt;

/// Polynomial of some degree `n`
///
/// Polynomial has a form: `f(x) = a_0 + a_1 * x^1 + ... + a_(n-1) * x^(n-1) + a_n * x^n`.
///
/// Coefficients `a_i` and indeterminate `x` are scalars in curve prime field,
/// ie. their type is `ECScalar` implementor.
#[derive(Derivative)]
#[derivative(Clone(bound = "P::Scalar: Clone"))]
#[derivative(Debug(bound = "P::Scalar: fmt::Debug"))]
pub struct Polynomial<P: ECPoint> {
    coefficients: Vec<P::Scalar>,
}

impl<P> Polynomial<P>
where
    P: ECPoint,
    P::Scalar: Clone,
{
    /// Constructs polynomial `f(x)` from list of coefficients `a`.
    ///
    /// ## Order
    ///
    /// `a[i]` should corresponds to coefficient `a_i` of polynomial `f(x) = ... + a_i * x^i + ...`
    ///
    /// ## Panics
    ///
    /// Panics if list of coefficients is empty
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coefs = vec![ECScalar::new_random(), ECScalar::new_random()];
    /// let poly = Polynomial::<GE>::from_coefficients(coefs.clone());
    ///
    /// assert_eq!(coefs, poly.coefficients());
    /// ```
    pub fn from_coefficients(coefficients: Vec<P::Scalar>) -> Self {
        assert!(
            !coefficients.is_empty(),
            "coefficients must have at least one coefficient"
        );
        Self { coefficients }
    }

    /// Sample a random polynomial of given degree
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let polynomial = Polynomial::<GE>::sample(3);
    /// assert_eq!(polynomial.degree(), 3);
    /// ```
    ///
    pub fn sample(degree: u16) -> Self {
        Polynomial {
            coefficients: iter::repeat_with(ECScalar::new_random)
                .take(usize::from(degree + 1))
                .collect(),
        }
    }

    /// Samples random polynomial of degree `n` with fixed coefficient `a_0 = coef0`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(3, coef0);
    /// assert_eq!(polynomial.evaluate(&FE::zero()), coef0);
    /// ```
    pub fn sample_fixed_coef0(n: u16, coef0: P::Scalar) -> Self {
        let random_coefficients = iter::repeat_with(ECScalar::new_random).take(usize::from(n));
        Polynomial {
            coefficients: iter::once(coef0).chain(random_coefficients).collect(),
        }
    }

    /// Takes scalar `x` and evaluates `f(x)`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// # use curv::arithmetic::BigInt;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(2, coef0);
    ///
    /// let x: FE = ECScalar::from(&BigInt::from(10));
    /// let y: FE = polynomial.evaluate(&x);
    ///
    /// let a = polynomial.coefficients();
    /// assert_eq!(y, a[0] + a[1] * x + a[2] * x*x);
    /// ```
    pub fn evaluate(&self, point_x: &P::Scalar) -> P::Scalar {
        let mut reversed_coefficients = self.coefficients.iter().rev();
        let head = reversed_coefficients
            .next()
            .expect("at least one coefficient is guaranteed to be present");
        let tail = reversed_coefficients;
        tail.fold(head.clone(), |partial, coef| {
            let partial_times_point_x = partial * point_x.clone();
            partial_times_point_x + coef.clone()
        })
    }

    /// Takes point `x` that's convertable to BigInt, and evaluates `f(x)`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// # use curv::arithmetic::BigInt;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(2, coef0);
    ///
    /// let x: u16 = 10;
    /// let y: FE = polynomial.evaluate_bigint(x);
    ///
    /// let a = polynomial.coefficients();
    /// let x: FE = ECScalar::from(&BigInt::from(x));
    /// assert_eq!(y, a[0] + a[1] * x + a[2] * x*x);
    /// ```
    pub fn evaluate_bigint<B>(&self, point_x: B) -> P::Scalar
    where
        BigInt: From<B>,
    {
        self.evaluate(&<P::Scalar as ECScalar>::from(&BigInt::from(point_x)))
    }

    /// Takes list of points `xs` and returns iterator over `f(xs[i])`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// # use curv::arithmetic::BigInt;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(2, coef0);
    ///
    /// let xs: &[FE] = &[ECScalar::from(&BigInt::from(10)), ECScalar::from(&BigInt::from(11))];
    /// let ys = polynomial.evaluate_many(xs);
    ///
    /// let a = polynomial.coefficients();
    /// for (y, x) in ys.zip(xs) {
    ///     assert_eq!(y, a[0] + a[1] * x + a[2] * x*x);
    /// }
    /// ```
    pub fn evaluate_many<'i, I>(&'i self, points_x: I) -> impl Iterator<Item = P::Scalar> + 'i
    where
        I: IntoIterator<Item = &'i P::Scalar> + 'i,
    {
        points_x.into_iter().map(move |x| self.evaluate(x))
    }

    /// Takes a list of points `xs` that are convertable to BigInt, and returns iterator over
    /// `f(xs[i])`.
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// # use curv::arithmetic::BigInt;
    /// use curv::elliptic::curves::p256::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(2, coef0);
    ///
    /// let xs: &[u16] = &[10, 11];
    /// let ys = polynomial.evaluate_many_bigint(xs.iter().copied());
    ///
    /// let a = polynomial.coefficients();
    /// for (y, x) in ys.zip(xs) {
    ///     let x: FE = ECScalar::from(&BigInt::from(*x));
    ///     assert_eq!(y, a[0] + a[1] * x + a[2] * x*x);
    /// }
    /// ```
    pub fn evaluate_many_bigint<'i, B, I>(
        &'i self,
        points_x: I,
    ) -> impl Iterator<Item = P::Scalar> + 'i
    where
        I: IntoIterator<Item = B> + 'i,
        BigInt: From<B>,
    {
        points_x.into_iter().map(move |x| self.evaluate_bigint(x))
    }

    /// Returns degree of polynomial
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// use curv::elliptic::curves::secp256_k1::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(3, coef0);
    /// assert_eq!(polynomial.degree(), 3);
    /// ```
    pub fn degree(&self) -> u16 {
        let len =
            u16::try_from(self.coefficients.len()).expect("degree guaranteed to fit into u16");
        len - 1
    }

    /// Returns list of polynomial coefficients `a`: `a[i]` corresponds to coefficient `a_i` of
    /// polynomial `f(x) = ... + a_i * x^i + ...`
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::Polynomial;
    /// # use curv::elliptic::curves::traits::ECScalar;
    /// use curv::elliptic::curves::secp256_k1::{GE, FE};
    ///
    /// let coef0: FE = ECScalar::new_random();
    /// let polynomial = Polynomial::<GE>::sample_fixed_coef0(3, coef0);
    /// assert_eq!(polynomial.coefficients()[0], coef0);
    /// ```
    pub fn coefficients(&self) -> &[P::Scalar] {
        &self.coefficients
    }
}

/// Multiplies polynomial `f(x)` at scalar `s`, returning resulting polynomial `g(x) = s * f(x)`
///
/// ## Example
///
/// ```rust
/// # use curv::cryptographic_primitives::Polynomial;
/// # use curv::elliptic::curves::traits::ECScalar;
/// use curv::elliptic::curves::secp256_k1::{GE, FE};
///
/// let f = Polynomial::<GE>::sample_fixed_coef0(3, ECScalar::new_random());
///
/// let s: FE = ECScalar::new_random();
/// let g = &f * &s;
///
/// for (f_coef, g_coef) in f.coefficients().iter().zip(g.coefficients()) {
///     assert_eq!(*f_coef * s, *g_coef);
/// }
/// ```
impl<P> ops::Mul<&P::Scalar> for &Polynomial<P>
where
    P: ECPoint,
    P::Scalar: Clone,
{
    type Output = Polynomial<P>;
    fn mul(self, scalar: &P::Scalar) -> Self::Output {
        let coefficients = self
            .coefficients
            .iter()
            .map(|c| c.clone() * scalar.clone())
            .collect();
        Polynomial::from_coefficients(coefficients)
    }
}

/// Adds two polynomial `f(x)` and `g(x)` returning resulting polynomial `h(x) = f(x) + g(x)`
///
/// ## Example
///
/// ```rust
/// # use curv::cryptographic_primitives::Polynomial;
/// # use curv::elliptic::curves::traits::ECScalar;
/// # use curv::arithmetic::BigInt;
/// use curv::elliptic::curves::secp256_k1::{GE, FE};
///
/// let f = Polynomial::<GE>::sample_fixed_coef0(2, ECScalar::new_random());
/// let g = Polynomial::<GE>::sample_fixed_coef0(3, ECScalar::new_random());
/// let h = &f + &g;
///
/// let x: FE = ECScalar::from(&BigInt::from(10));
/// assert_eq!(h.evaluate(&x), f.evaluate(&x) + g.evaluate(&x));
/// ```
impl<P> ops::Add for &Polynomial<P>
where
    P: ECPoint,
    P::Scalar: Clone,
{
    type Output = Polynomial<P>;
    fn add(self, g: Self) -> Self::Output {
        let len1 = self.coefficients.len();
        let len2 = g.coefficients.len();

        let overlapped = self
            .coefficients()
            .iter()
            .zip(g.coefficients())
            .map(|(f_coef, g_coef)| f_coef.clone() + g_coef.clone());
        let tail = if len1 < len2 {
            &g.coefficients()[len1..]
        } else {
            &self.coefficients()[len2..]
        };

        Polynomial::from_coefficients(overlapped.chain(tail.iter().cloned()).collect())
    }
}

/// Subtracts two polynomial `g(x)` from `f(x)` returning resulting polynomial `h(x) = f(x) - g(x)`
///
/// ## Example
///
/// ```rust
/// # use curv::cryptographic_primitives::Polynomial;
/// # use curv::elliptic::curves::traits::ECScalar;
/// # use curv::arithmetic::BigInt;
/// use curv::elliptic::curves::secp256_k1::{GE, FE};
///
/// let f = Polynomial::<GE>::sample_fixed_coef0(2, ECScalar::new_random());
/// let g = Polynomial::<GE>::sample_fixed_coef0(3, ECScalar::new_random());
/// let h = &f - &g;
///
/// let x: FE = ECScalar::from(&BigInt::from(10));
/// assert_eq!(h.evaluate(&x), f.evaluate(&x).sub(&g.evaluate(&x).get_element()));
/// ```
impl<P> ops::Sub for &Polynomial<P>
where
    P: ECPoint,
    P::Scalar: Clone,
{
    type Output = Polynomial<P>;
    fn sub(self, g: Self) -> Self::Output {
        let len1 = self.coefficients.len();
        let len2 = g.coefficients.len();

        let overlapped = self
            .coefficients()
            .iter()
            .zip(g.coefficients())
            .map(|(f_coef, g_coef)| f_coef.sub(&g_coef.get_element()));
        let tail = if len1 < len2 {
            // Instead of evaluating (0 - s), we use a trick and evaluate ((1 - s) - 1).
            // The reason why we do this - some of scalars cannot be constructed to be zero (
            // panic will be raised)
            let one: P::Scalar = ECScalar::from(&BigInt::from(1));
            g.coefficients()[len1..]
                .iter()
                .map(|x| one.sub(&x.get_element()).sub(&one.get_element()))
                .collect()
        } else {
            self.coefficients()[len2..].to_vec()
        };

        Polynomial::from_coefficients(overlapped.chain(tail.into_iter()).collect())
    }
}
