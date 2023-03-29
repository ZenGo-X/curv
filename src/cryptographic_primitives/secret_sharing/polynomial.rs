use std::cmp::Ordering;
use std::convert::TryFrom;
use std::{iter, ops};

use serde::{Deserialize, Serialize};

use crate::elliptic::curves::{Curve, Scalar};

/// Degree of a [polynomial](Polynomial).
///
/// For a polynomial of the form: $f(x) = a_0 + a_1 x^1 + \dots{} + a_{n-1} x^{n-1} + a_n x^n$
///
/// The degree of $f(x)$ is defined as the biggest $i$ such that $a_i \neq 0$.
/// If $f(x) = 0$ it's degree is defined as $\infty$.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolynomialDegree {
    Infinity,
    Finite(u16),
}

impl From<u16> for PolynomialDegree {
    fn from(deg: u16) -> Self {
        PolynomialDegree::Finite(deg)
    }
}

impl PartialOrd for PolynomialDegree {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PolynomialDegree {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Infinity, Self::Infinity) => Ordering::Equal,
            (Self::Infinity, Self::Finite(_)) => Ordering::Greater,
            (Self::Finite(_), Self::Infinity) => Ordering::Less,
            (Self::Finite(a), Self::Finite(b)) => a.cmp(b),
        }
    }
}

/// Polynomial of some degree $n$
///
/// Polynomial has a form: $f(x) = a_0 + a_1 x^1 + \dots{} + a_{n-1} x^{n-1} + a_n x^n$
///
/// Coefficients $a_i$ and indeterminate $x$ are in $\Zq$, ie. they are [`Scalar<E>`](Scalar).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Polynomial<E: Curve> {
    coefficients: Vec<Scalar<E>>,
}

impl<E: Curve> Polynomial<E> {
    /// Constructs polynomial $f(x)$ from list of coefficients $a_0, \dots, a_n$ in $\Zq$
    ///
    /// ## Order
    ///
    /// $a_i$ should corresponds to polynomial $i^{\text{th}}$ coefficient $f(x) = \dots{} + a_i x^i + \dots$
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
    /// use curv::cryptographic_primitives::secret_sharing::PolynomialDegree;
    ///
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact(3);
    /// assert_eq!(polynomial.degree(), 3.into());
    ///
    /// let zero_polynomial = Polynomial::<Secp256k1>::sample_exact(PolynomialDegree::Infinity);
    /// assert_eq!(zero_polynomial.degree(), PolynomialDegree::Infinity);
    /// ```
    pub fn sample_exact(degree: impl Into<PolynomialDegree>) -> Self {
        match degree.into() {
            PolynomialDegree::Finite(degree) => Self::from_coefficients(
                iter::repeat_with(Scalar::random)
                    .take(usize::from(degree) + 1)
                    .collect(),
            ),
            PolynomialDegree::Infinity => Self::from_coefficients(vec![]),
        }
    }

    /// Samples random polynomial of degree $n$ with fixed constant term (ie. $a_0 = \text{constant\\_term}$)
    ///
    /// ## Example
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let const_term = Scalar::<Secp256k1>::random();
    /// let polynomial = Polynomial::<Secp256k1>::sample_exact_with_fixed_const_term(3, const_term.clone());
    /// assert_eq!(polynomial.degree(), 3.into());
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

    /// Returns degree $d$ of polynomial $f(x)$: $d = \deg f$
    ///
    /// ```rust
    /// # use curv::cryptographic_primitives::secret_sharing::{Polynomial, PolynomialDegree};
    /// use curv::elliptic::curves::{Secp256k1, Scalar};
    ///
    /// let polynomial = Polynomial::<Secp256k1>::from_coefficients(vec![
    ///     Scalar::from(1), Scalar::from(2),
    /// ]);
    /// assert_eq!(polynomial.degree(), 1.into());
    ///
    /// let polynomial = Polynomial::<Secp256k1>::from_coefficients(vec![
    ///     Scalar::zero()
    /// ]);
    /// assert_eq!(polynomial.degree(), PolynomialDegree::Infinity);
    /// ```
    pub fn degree(&self) -> PolynomialDegree {
        self.coefficients()
            .iter()
            .enumerate()
            .rev()
            .find(|(_, a)| !a.is_zero())
            .map(|(i, _)| {
                PolynomialDegree::Finite(
                    u16::try_from(i).expect("polynomial degree guaranteed to fit into u16"),
                )
            })
            .unwrap_or(PolynomialDegree::Infinity)
    }

    /// Takes scalar $x$ and evaluates $f(x)$
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

    /// Takes point $x$ that's convertable to BigInt, and evaluates $f(x)$
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

    /// Takes list of points $x$ and returns iterator over $f(x_i)$
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

    /// Takes a list of points $x$ that are convertable to BigInt, and returns iterator over
    /// $f(x_i)$.
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

    /// Returns list of polynomial coefficients $a$: $a_i$ corresponds to $i^{\text{th}}$ coefficient of
    /// polynomial $f(x) = \dots{} + a_i x^i + \dots{}$
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

    /// Evaluates lagrange basis polynomial
    ///
    /// $$l_{X,j}(x) = \prod_{\substack{0 \leq m \leq t,\\\\m \ne j}} \frac{x - X_m}{X_j - X_m}$$
    ///
    /// Lagrange basis polynomials are mainly used for Lagrange interpolation, ie. calculating $L(x)$
    /// where polynomial $L$ is defined as set of $t+1$ distinct points $(x_i, y_i)$ ($t = \deg f$).
    /// Example section shows how Lagrange interpolation can be implemented using this function.
    ///
    /// ## Panics
    /// This function will panic if elements in `xs` are not pairwise distinct, or `j ≥ xs.len()`
    ///
    /// ## Example
    /// If you have polynomial $f$ defined as $t+1$ points $(x_0, y_0), \dots, (x_t, y_t)$ (and polynomial
    /// degree is $t$), then you can, for instance, calculate $f(15)$ using Lagrange interpolation:
    ///
    /// ```rust
    /// use curv::cryptographic_primitives::secret_sharing::Polynomial;
    /// # use curv::elliptic::curves::*;
    ///
    /// # let t = 3;
    /// # let f = Polynomial::<Secp256r1>::sample_exact(t);
    /// # let (x_0, x_1, x_2, x_3) = (Scalar::from(1), Scalar::from(2), Scalar::from(3), Scalar::from(4));
    /// # let (y_0, y_1, y_2, y_3) = (f.evaluate(&x_0), f.evaluate(&x_1), f.evaluate(&x_2), f.evaluate(&x_3));
    /// let xs = &[x_0, x_1, x_2, x_3];
    /// let ys = &[y_0, y_1, y_2, y_3];
    ///
    /// let f_15: Scalar<_> = (0..).zip(ys)
    ///     .map(|(j, y_j)| y_j * Polynomial::lagrange_basis(&Scalar::from(15), j, xs))
    ///     .sum();
    /// assert_eq!(f_15, f.evaluate(&Scalar::from(15)));
    /// ```
    ///
    /// Generally, formula of Lagrange interpolation is:
    ///
    /// $$ L_{X,Y}(x) = \sum^t_{j=0} Y\_j \cdot l_{X,j}(x) $$
    pub fn lagrange_basis(x: &Scalar<E>, j: u16, xs: &[Scalar<E>]) -> Scalar<E> {
        let x_j = &xs[usize::from(j)];
        let num: Scalar<E> = (0u16..)
            .zip(xs)
            .filter(|(m, _)| *m != j)
            .map(|(_, x_m)| x - x_m)
            .product();
        let denum: Scalar<E> = (0u16..)
            .zip(xs)
            .filter(|(m, _)| *m != j)
            .map(|(_, x_m)| x_j - x_m)
            .product();
        let denum = denum
            .invert()
            .expect("elements in xs are not pairwise distinct");
        num * denum
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
