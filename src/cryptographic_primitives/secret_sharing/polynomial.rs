use std::convert::TryFrom;
use std::{iter, ops};

use crate::elliptic::curves::{Curve, Scalar};

/// Polynomial of some degree `n`
///
/// Polynomial has a form: `f(x) = a_0 + a_1 * x^1 + ... + a_(n-1) * x^(n-1) + a_n * x^n`.
///
/// Coefficients `a_i` and indeterminate `x` are scalars in curve prime field,
/// ie. their type is `ECScalar` implementor.
#[derive(Clone, Debug)]
pub struct Polynomial<E: Curve> {
    coefficients: Vec<Scalar<E>>,
}

impl<E: Curve> Polynomial<E> {
    /// Constructs polynomial `f(x)` from list of coefficients `a`
    ///
    /// ## Order
    ///
    /// `a[i]` should corresponds to coefficient `a_i` of polynomial `f(x) = ... + a_i * x^i + ...`
    ///
    /// ## Polynomial degree
    ///
    /// Note that it's not guaranteed that constructed polynomial degree equals to `coefficients.len()-1`
    /// as it's allowed to end with zero coefficients. Actual polynomial degree equals to index of last
    /// non-zero coefficient or zero if all the coefficients are zero.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Scalar, Point, Secp256k1};
    ///
    /// let coefs = vec![Scalar::random(), Scalar::random()];
    /// let poly = Polynomial::<Secp256k1>::from_coefficients(coefs.clone());
    ///
    /// assert_eq!(coefs, poly.coefficients());
    /// ```
    pub fn from_coefficients(coefficients: Vec<Scalar<E>>) -> Self {
        Self { coefficients }
    }

    /// Sample a random polynomial of given degree
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::Secp256k1;
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(3);
    /// assert_eq!(polynomial.degree(), 3);
    /// ```
    pub fn sample_exact(degree: u16) -> Self {
        Self::from_coefficients(
            iter::repeat_with(Scalar::random)
                .take(usize::from(degree + 1))
                .collect(),
        )
    }

    /// Samples random polynomial of degree `n` with fixed constant term (ie. `a_0 = constant_term`)
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let const_term = Scalar::<Secp256k1>::random();
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact_with_fixed_const_term(3, const_term.clone());
    /// assert_eq!(polynomial.degree(), 3);
    /// assert_eq!(polynomial.evaluate(&Scalar::zero()), const_term);
    /// ```
    pub fn sample_exact_with_fixed_const_term(n: u16, const_term: Scalar<E>) -> Self {
        if n == 0 {
            Self::from_coefficients(vec![const_term])
        } else {
            let random_coefficients = iter::repeat_with(Scalar::random).take(usize::from(n));
            Self::from_coefficients(iter::once(const_term).chain(random_coefficients).collect())
        }
    }

    /// Returns degree `d` of polynomial `f(x)`: `d = deg(f)`
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::from_coefficients(vec![
    ///     Scalar::from(1), Scalar::from(2),
    /// ]);
    /// assert_eq!(polynomial.degree(), 1);
    ///
    /// let polynomial = Polynomial::<Secp256k1>::from_coefficients(vec![
    ///     Scalar::from(1), Scalar::zero(),
    /// ]);
    /// assert_eq!(polynomial.degree(), 0);
    /// ```
    pub fn degree(&self) -> u16 {
        let i = self
            .coefficients()
            .iter()
            .enumerate()
            .rev()
            .find(|(_, a)| !a.is_zero())
            .map(|(i, _)| i)
            .unwrap_or(0);
        u16::try_from(i).expect("polynomial degree guaranteed to fit into u16")
    }

    /// Takes scalar `x` and evaluates `f(x)`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(2);
    ///
    /// let x = Scalar::from(10);
    /// let y = polynomial.evaluate(&x);
    ///
    /// let a = polynomial.coefficients();
    /// assert_eq!(y, &a[0] + &a[1] * &x + &a[2] * &x*&x);
    /// ```
    pub fn evaluate(&self, point_x: &Scalar<E>) -> Scalar<E> {
        let mut reversed_coefficients = self.coefficients.iter().rev();
        let head = reversed_coefficients
            .next()
            .expect("at least one coefficient is guaranteed to be present");
        let tail = reversed_coefficients;
        tail.fold(head.clone(), |partial, coef| {
            let partial_times_point_x = partial * point_x;
            partial_times_point_x + coef
        })
    }

    /// Takes point `x` that's convertable to BigInt, and evaluates `f(x)`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(2);
    ///
    /// let x: u16 = 10;
    /// let y: Scalar<Secp256k1> = polynomial.evaluate_bigint(x);
    ///
    /// let a = polynomial.coefficients();
    /// let x = Scalar::from(x);
    /// assert_eq!(y, &a[0] + &a[1] * &x + &a[2] * &x*&x);
    /// ```
    pub fn evaluate_bigint<B>(&self, point_x: B) -> Scalar<E>
    where
        Scalar<E>: From<B>,
    {
        self.evaluate(&Scalar::from(point_x))
    }

    /// Takes list of points `xs` and returns iterator over `f(xs[i])`
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(2);
    ///
    /// let xs = &[Scalar::from(10), Scalar::from(11)];
    /// let ys = polynomial.evaluate_many(xs);
    ///
    /// let a = polynomial.coefficients();
    /// for (y, x) in ys.zip(xs) {
    ///     assert_eq!(y, &a[0] + &a[1] * x + &a[2] * x*x);
    /// }
    /// ```
    pub fn evaluate_many<'i, I>(&'i self, points_x: I) -> impl Iterator<Item = Scalar<E>> + 'i
    where
        I: IntoIterator<Item = &'i Scalar<E>> + 'i,
    {
        points_x.into_iter().map(move |x| self.evaluate(x))
    }

    /// Takes a list of points `xs` that are convertable to BigInt, and returns iterator over
    /// `f(xs[i])`.
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(2);
    ///
    /// let xs: &[u16] = &[10, 11];
    /// let ys = polynomial.evaluate_many_bigint(xs.iter().copied());
    ///
    /// let a = polynomial.coefficients();
    /// for (y, x) in ys.zip(xs) {
    ///     let x = Scalar::from(*x);
    ///     assert_eq!(y, &a[0] + &a[1] * &x + &a[2] * &x*&x);
    /// }
    /// ```
    pub fn evaluate_many_bigint<'i, B, I>(
        &'i self,
        points_x: I,
    ) -> impl Iterator<Item = Scalar<E>> + 'i
    where
        I: IntoIterator<Item = B> + 'i,
        Scalar<E>: From<B>,
    {
        points_x.into_iter().map(move |x| self.evaluate_bigint(x))
    }

    /// Returns list of polynomial coefficients `a`: `a[i]` corresponds to coefficient `a_i` of
    /// polynomial `f(x) = ... + a_i * x^i + ...`
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(3);
    /// let a = polynomial.coefficients();
    /// let x = Scalar::<Secp256k1>::random();
    /// assert_eq!(polynomial.evaluate(&x), &a[0] + &a[1] * &x + &a[2] * &x*&x + &a[3] * &x*&x*&x);
    /// ```
    pub fn coefficients(&self) -> &[Scalar<E>] {
        &self.coefficients
    }
}

/// Multiplies polynomial `f(x)` at scalar `s`, returning resulting polynomial `g(x) = s * f(x)`
///
/// ## Example
///
/// ```rust
/// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
/// use curv::elliptic::curves::{Secp256k1, Scalar};
///
/// let f = Polynomial::<Secp256k1>::sample_exact(3);
///
/// let s = Scalar::<Secp256k1>::random();
/// let g = &f * &s;
///
/// for (f_coef, g_coef) in f.coefficients().iter().zip(g.coefficients()) {
///     assert_eq!(&(f_coef * &s), g_coef);
/// }
/// ```
impl<E: Curve> ops::Mul<&Scalar<E>> for &Polynomial<E> {
    type Output = Polynomial<E>;
    fn mul(self, scalar: &Scalar<E>) -> Self::Output {
        let coefficients = self.coefficients.iter().map(|c| c * scalar).collect();
        Polynomial::from_coefficients(coefficients)
    }
}

/// Adds two polynomial `f(x)` and `g(x)` returning resulting polynomial `h(x) = f(x) + g(x)`
///
/// ## Example
///
/// ```rust
/// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
/// use curv::elliptic::curves::{Secp256k1, Scalar};
///
/// let f = Polynomial::<Secp256k1>::sample_exact(2);
/// let g = Polynomial::<Secp256k1>::sample_exact(3);
/// let h = &f + &g;
///
/// let x = Scalar::<Secp256k1>::from(10);
/// assert_eq!(h.evaluate(&x), f.evaluate(&x) + g.evaluate(&x));
/// ```
impl<E: Curve> ops::Add for &Polynomial<E> {
    type Output = Polynomial<E>;
    fn add(self, g: Self) -> Self::Output {
        let len1 = self.coefficients.len();
        let len2 = g.coefficients.len();

        let overlapped = self
            .coefficients()
            .iter()
            .zip(g.coefficients())
            .map(|(f_coef, g_coef)| f_coef + g_coef);
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
/// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
/// use curv::elliptic::curves::{Secp256k1, Scalar};
///
/// let f = Polynomial::<Secp256k1>::sample_exact(2);
/// let g = Polynomial::<Secp256k1>::sample_exact(3);
/// let h = &f - &g;
///
/// let x = Scalar::<Secp256k1>::from(10);
/// assert_eq!(h.evaluate(&x), f.evaluate(&x) - &g.evaluate(&x));
/// ```
impl<E: Curve> ops::Sub for &Polynomial<E> {
    type Output = Polynomial<E>;
    fn sub(self, g: Self) -> Self::Output {
        let len1 = self.coefficients.len();
        let len2 = g.coefficients.len();

        let overlapped = self
            .coefficients()
            .iter()
            .zip(g.coefficients())
            .map(|(f_coef, g_coef)| f_coef - g_coef);
        let tail = if len1 < len2 {
            g.coefficients()[len1..].iter().map(|x| -x).collect()
        } else {
            self.coefficients()[len2..].to_vec()
        };

        Polynomial::from_coefficients(overlapped.chain(tail.into_iter()).collect())
    }
}
