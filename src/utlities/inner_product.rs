/*

Copyright 2020 by Kzen Networks

Copyright information here.

@license GPL-3.0+ <link>
*/

// based on the paper: https://eprint.iacr.org/2017/1066.pdf

#![allow(non_snake_case)]

// use crate::protocols::bulletproofs::Field;
// use crate::protocols::bulletproofs::Group;
use crate::BulletproofError::{self, InnerProductError};
use curv::arithmetic::traits::Modulo;
use crate::utlities::create_hash;
use curv::BigInt;
use curv::arithmetic::One;
use curv::arithmetic::Zero;
use elgamal::ElGamalPP;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub pp: ElGamalPP,
    pub g: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Field {
    pub pp: ElGamalPP,
    pub x: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct InnerProductArg {
    pub(super) L: Vec<Group>,
    pub(super) R: Vec<Group>,
    pub(super) a_tag: Field,
    pub(super) b_tag: Field,
}

impl InnerProductArg {
    pub fn prove(
        G: &[Group],
        H: &[Group],
        ux: &Group,
        P: &Group,
        a: &[Field],
        b: &[Field],
        mut L_vec: Vec<Group>,
        mut R_vec: Vec<Group>,
    ) -> InnerProductArg {
        let n = G.len();
        let order = a[0].pp.q.clone();
        let params = a[0].pp.clone();

        // All of the input vectors must have the same length.
        assert_eq!(G.len(), n);
        assert_eq!(H.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);
        assert!(n.is_power_of_two());

        if n != 1 {
            let n = n / 2;
            let (a_L, a_R) = a.split_at(n);
            let (b_L, b_R) = b.split_at(n);
            let (G_L, G_R) = G.split_at(n);
            let (H_L, H_R) = H.split_at(n);

            let c_L = scalar_inner_product(&a_L, &b_R);
            let c_R = scalar_inner_product(&a_R, &b_L);

            // compute L
            let mut scalars_L: Vec<Field> = Vec::with_capacity(2 * n + 1);
            scalars_L.push(c_L);
            scalars_L.extend_from_slice(&a_L);
            scalars_L.extend_from_slice(&b_R);
            let mut elements_L: Vec<Group> = Vec::with_capacity(2 * n + 1);
            elements_L.push(ux.clone());
            elements_L.extend_from_slice(&G_R);
            elements_L.extend_from_slice(&H_L);
            let L = multiexponentiation(&elements_L, &scalars_L);
            L_vec.push(L.clone());

            // compute R
            let mut scalars_R: Vec<Field> = Vec::with_capacity(2 * n + 1);
            scalars_R.push(c_R);
            scalars_R.extend_from_slice(&a_R);
            scalars_R.extend_from_slice(&b_L);
            let mut elements_R: Vec<Group> = Vec::with_capacity(2 * n + 1);
            elements_R.push(ux.clone());
            elements_R.extend_from_slice(&G_L);
            elements_R.extend_from_slice(&H_R);
            let R = multiexponentiation(&elements_R, &scalars_R);
            R_vec.push(R.clone());

            // generate challenge
            let x = create_hash(&[&L.g, &R.g, &ux.g]); //TODO: challenge should be of size |q|
            let x = x.modulus(&order);
            let x_inv = BigInt::mod_inv(&x, &order).unwrap();

            // update secret vectors for next round
            let a_new = (0..n)
                .map(|i| {
                    let aLx = BigInt::mod_mul(&a_L[i].x, &x, &order);
                    let aR_minusx = BigInt::mod_mul(&a_R[i].x, &x_inv, &order);
                    let a_new_scalar = BigInt::mod_add(&aLx, &aR_minusx, &order);
                    Field {
                        pp: params.clone(),
                        x: a_new_scalar,
                    }
                })
                .collect::<Vec<Field>>();

            let b_new = (0..n)
                .map(|i| {
                    let bRx = BigInt::mod_mul(&b_R[i].x, &x, &order);
                    let bL_minusx = BigInt::mod_mul(&b_L[i].x, &x_inv, &order);
                    let b_new_scalar = BigInt::mod_add(&bRx, &bL_minusx, &order);
                    Field {
                        pp: params.clone(),
                        x: b_new_scalar,
                    }
                })
                .collect::<Vec<Field>>();

            let p = a[0].pp.p.clone();
            // update generator vectors
            let G_new = (0..n)
                .map(|i| {
                    let GLx_inv = BigInt::mod_pow(&G_L[i].g, &x_inv, &p);
                    let GRx = BigInt::mod_pow(&G_R[i].g, &x, &p);
                    let G_new_element = BigInt::mod_mul(&GRx, &GLx_inv, &p);
                    // println!("G[{}] = {}", i, G_new_element);
                    Group {
                        pp: params.clone(),
                        g: G_new_element,
                    }
                })
                .collect::<Vec<Group>>();

            let H_new = (0..n)
                .map(|i| {
                    let HLx = BigInt::mod_pow(&H_L[i].g, &x, &p);
                    let HRx_inv = BigInt::mod_pow(&H_R[i].g, &x_inv, &p);
                    let H_new_element = BigInt::mod_mul(&HRx_inv, &HLx, &p);
                    // println!("H[{}] = {}", i, H_new_element);
                    Group {
                        pp: params.clone(),
                        g: H_new_element,
                    }
                })
                .collect::<Vec<Group>>();

            return InnerProductArg::prove(&G_new, &H_new, &ux, &P, &a_new, &b_new, L_vec, R_vec);
        }

        InnerProductArg {
            L: L_vec,
            R: R_vec,
            a_tag: a[0].clone(),
            b_tag: b[0].clone(),
        }
    }

    pub fn verify(
        &self,
        g_vec: &[Group],
        hi_tag: &[Group],
        ux: &Group,
        P: &Group,
    ) -> Result<(), BulletproofError> {
        let G = &g_vec[..];
        let H = &hi_tag[..];
        let n = G.len();
        let order = ux.pp.q.clone();
        let p = ux.pp.p.clone();
        let params = ux.pp.clone();

        // All of the input vectors must have the same length.
        assert_eq!(H.len(), n);
        assert!(n.is_power_of_two());

        if n != 1 {
            let n = n / 2;
            let (G_L, G_R) = G.split_at(n);
            let (H_L, H_R) = H.split_at(n);

            // generate challenge
            let x = create_hash(&[&self.L[0].g, &self.R[0].g, &ux.g]);
            let x = x.modulus(&order);

            let x_inv = BigInt::mod_inv(&x, &order).unwrap();
            let x_sq = BigInt::mod_mul(&x, &x, &order);
            let x_inv_sq = BigInt::mod_mul(&x_inv, &x_inv, &order);

            // update generator vectors
            let G_new = (0..n)
                .map(|i| {
                    let GLx_inv = BigInt::mod_pow(&G_L[i].g, &x_inv, &p);
                    let GRx = BigInt::mod_pow(&G_R[i].g, &x, &p);
                    let G_new_element = BigInt::mod_mul(&GRx, &GLx_inv, &p);
                    // println!("G[{}] = {}", i, G_new_element);
                    Group {
                        pp: params.clone(),
                        g: G_new_element,
                    }
                })
                .collect::<Vec<Group>>();

            let H_new = (0..n)
                .map(|i| {
                    let HLx = BigInt::mod_pow(&H_L[i].g, &x, &p);
                    let HRx_inv = BigInt::mod_pow(&H_R[i].g, &x_inv, &p);
                    let H_new_element = BigInt::mod_mul(&HRx_inv, &HLx, &p);
                    // println!("H[{}] = {}", i, H_new_element);
                    Group {
                        pp: params.clone(),
                        g: H_new_element,
                    }
                })
                .collect::<Vec<Group>>();

            // updating P
            let Lx_sq = BigInt::mod_pow(&self.L[0].g, &x_sq, &p);
            let Rx_inv_sq = BigInt::mod_pow(&self.R[0].g, &x_inv_sq, &p);
            let Lx_Rx_inv = BigInt::mod_mul(&Lx_sq, &Rx_inv_sq, &p);
            let P_new = Group {
                pp: params.clone(),
                g: BigInt::mod_mul(&P.g, &Lx_Rx_inv, &p),
            };

            // recursive computation
            let ip = InnerProductArg {
                L: (&self.L[1..]).to_vec(),
                R: (&self.R[1..]).to_vec(),
                a_tag: self.a_tag.clone(),
                b_tag: self.b_tag.clone(),
            };
            return ip.verify(&G_new, &H_new, ux, &P_new);
        }

        // final verification check
        let c = BigInt::mod_mul(&self.a_tag.x, &self.b_tag.x, &order);
        let G_times_a = BigInt::mod_pow(&G[0].g, &self.a_tag.x, &p);
        let H_times_b = BigInt::mod_pow(&H[0].g, &self.b_tag.x, &p);
        let Ga_Hb = BigInt::mod_mul(&G_times_a, &H_times_b, &p);
        let ux_c = BigInt::mod_pow(&ux.g, &c, &p);
        let P_calc = BigInt::mod_mul(&Ga_Hb, &ux_c, &p);

        // println!("c = {}\nGa = {}\nHb = {}", c, G_times_a, H_times_b);
        // println!("P_ver = {}", P_calc);

        if P.g.clone() == P_calc {
            Ok(())
        } else {
            Err(InnerProductError)
        }
    }

    ///
    /// Returns Ok() if the given inner product satisfies the verification equations,
    /// else returns `InnerProductError`.
    ///
    /// Uses a single multiexponentiation (multiscalar multiplication in additive notation)
    /// check to verify an inner product proof.
    ///
    pub fn fast_verify(
        &self,
        g_vec: &[Group],
        hi_tag: &[Group],
        ux: &Group,
        P: &Group,
    ) -> Result<(), BulletproofError> {
        let G = &g_vec[..];
        let H = &hi_tag[..];
        let n = G.len();
        let order = ux.pp.q.clone();
        let p = ux.pp.p.clone();

        // let params = ux.pp.clone();

        // All of the input vectors must have the same length.
        assert_eq!(H.len(), n);
        assert!(n.is_power_of_two());

        let lg_n = self.L.len();
        assert!(
            lg_n <= 64,
            "Not compatible for vector sizes greater than 2^64!"
        );

        let mut x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_n);
        let mut x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_n);
        let mut minus_x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_n);
        let mut minus_x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_n);
        let mut allinv = BigInt::one();
        for (Li, Ri) in self.L.iter().zip(self.R.iter()) {
            let x = create_hash(&[&Li.g, &Ri.g, &ux.g]);
            let x = x.modulus(&order);

            let x_inv = BigInt::mod_inv(&x, &order).unwrap();
            let x_sq = BigInt::mod_pow(&x, &BigInt::from(2), &order);
            let x_inv_sq = BigInt::mod_pow(&x_inv, &BigInt::from(2), &order);

            x_sq_vec.push(x_sq.clone());
            x_inv_sq_vec.push(x_inv_sq.clone());
            minus_x_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_sq, &order));
            minus_x_inv_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_inv_sq, &order));
            allinv = BigInt::mod_mul(&allinv, &x_inv, &order);
        }

        let mut s: Vec<BigInt> = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i =
                (std::mem::size_of_val(&n) * 8) - 1 - ((i as usize).leading_zeros() as usize);
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [x_k,...,x_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let x_lg_i_sq = x_sq_vec[(lg_n - 1) - lg_i].clone();
            s.push(s[i - k].clone() * x_lg_i_sq);
        }

        let a_times_s: Vec<BigInt> = (0..n)
            .map(|i| BigInt::mod_mul(&s[i], &self.a_tag.x, &order))
            .collect();

        let b_div_s: Vec<BigInt> = (0..n)
            .map(|i| {
                let s_inv_i = BigInt::mod_inv(&s[i], &order).unwrap();
                BigInt::mod_mul(&s_inv_i, &self.b_tag.x, &order)
            })
            .collect();
        let c = BigInt::mod_mul(&self.a_tag.x, &self.b_tag.x, &order);

        let mut scalars: Vec<BigInt> = Vec::with_capacity(2 * n + 2 * lg_n + 2);
        scalars.extend_from_slice(&a_times_s);
        scalars.extend_from_slice(&b_div_s);
        scalars.extend_from_slice(&minus_x_sq_vec);
        scalars.extend_from_slice(&minus_x_inv_sq_vec);
        scalars.push(c);

        let mut points: Vec<Group> = Vec::with_capacity(2 * n + 2 * lg_n + 2);
        points.extend_from_slice(g_vec);
        points.extend_from_slice(hi_tag);
        points.extend_from_slice(&self.L);
        points.extend_from_slice(&self.R);
        points.push(ux.clone());

        let tot_len = points.len();
        let expect_P = (0..tot_len)
            .map(|i| BigInt::mod_pow(&points[i].g, &scalars[i], &p))
            .fold(BigInt::one(), |acc, x| BigInt::mod_mul(&acc, &x, &p));

        if P.g == expect_P {
            Ok(())
        } else {
            Err(InnerProductError)
        }
    }
}

pub fn scalar_inner_product(a: &[Field], b: &[Field]) -> Field {
    assert_eq!(
        a.len(),
        b.len(),
        "inner_product(a,b): lengths of vectors do not match"
    );
    let out = BigInt::zero();
    let order = a[0].pp.q.clone(); // TODO: check both a and b have the same params
    let out = a.iter().zip(b).fold(out, |acc, var| {
        let aibi = BigInt::mod_mul(&(var.0).x, &(var.1).x, &order);
        BigInt::mod_add(&acc, &aibi, &order)
    });
    return Field {
        pp: a[0].pp.clone(),
        x: out,
    };
}

pub fn multiexponentiation(elements: &[Group], scalars: &[Field]) -> Group {
    assert_eq!(
        scalars.len(),
        elements.len(),
        "multiexponentiation(a,g): lengths of vectors do not match"
    );
    let out = BigInt::one();
    let order = scalars[0].pp.p.clone();
    let out = elements.iter().zip(scalars).fold(out, |acc, var| {
        let temp = BigInt::mod_pow(&(var.0).g, &(var.1).x, &order);
        BigInt::mod_mul(&acc, &temp, &order)
    });
    return Group {
        pp: scalars[0].pp.clone(),
        g: out,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalPP;

    fn test_helper(n: usize) {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);

        let g_vec = (0..n)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                Group {
                    pp: params.clone(),
                    g: BigInt::mod_pow(&params.g, &r, &params.p),
                }
            })
            .collect::<Vec<Group>>();

        let h_vec = (0..n)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                Group {
                    pp: params.clone(),
                    g: BigInt::mod_pow(&params.g, &r, &params.p),
                }
            })
            .collect::<Vec<Group>>();

        let r = BigInt::sample_below(&params.q);
        let Gx = Group {
            pp: params.clone(),
            g: BigInt::mod_pow(&params.g, &r, &params.p),
        };

        let a: Vec<_> = (0..n)
            .map(|_| Field {
                pp: params.clone(),
                x: BigInt::sample_below(&params.q),
            })
            .collect();

        let b: Vec<_> = (0..n)
            .map(|_| Field {
                pp: params.clone(),
                x: BigInt::sample_below(&params.q),
            })
            .collect();

        let c = super::scalar_inner_product(&a, &b);

        let y = Field {
            pp: params.clone(),
            x: BigInt::sample_below(&params.q),
        };
        let y_vec = (0..n).map(|_| y.clone()).collect::<Vec<Field>>();
        let hi_tag = (0..n)
            .map(|i| {
                let hi_yi = BigInt::mod_pow(&h_vec[i].g, &y_vec[i].x, &params.p);
                Group {
                    pp: params.clone(),
                    g: hi_yi,
                }
            })
            .collect::<Vec<Group>>();

        // compute pedersen vector commitment P
        let ux_c = BigInt::mod_pow(&Gx.g, &c.x, &params.p);
        let G_pow_a = multiexponentiation(&g_vec, &a);
        let H_pow_b = multiexponentiation(&hi_tag, &b);
        let Ga_Hb = BigInt::mod_mul(&G_pow_a.g, &H_pow_b.g, &params.p);
        let P = Group {
            pp: params.clone(),
            g: BigInt::mod_mul(&Ga_Hb, &ux_c, &params.p),
        };

        // println!("c = {}\nGa = {}\nHb = {}", c.x, G_pow_a.g, H_pow_b.g);
        // println!("P_test = {}", P.g);

        let L_vec = Vec::with_capacity(n);
        let R_vec = Vec::with_capacity(n);
        let ipp = InnerProductArg::prove(&g_vec, &hi_tag, &Gx, &P, &a, &b, L_vec, R_vec);
        let verifier = ipp.fast_verify(&g_vec, &hi_tag, &Gx, &P);
        assert!(verifier.is_ok())
    }

    #[test]
    fn scalar_inner_product_test() {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let mut a: Vec<Field> = Vec::new();
        let mut b: Vec<Field> = Vec::new();
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(9),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(2),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(5),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(17),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(13),
        });

        b.push(Field {
            pp: params.clone(),
            x: BigInt::from(19),
        });
        b.push(Field {
            pp: params.clone(),
            x: BigInt::from(3),
        });
        b.push(Field {
            pp: params.clone(),
            x: BigInt::from(6),
        });
        b.push(Field {
            pp: params.clone(),
            x: BigInt::from(12),
        });
        b.push(Field {
            pp: params.clone(),
            x: BigInt::from(7),
        });

        assert_eq!(BigInt::from(502), scalar_inner_product(&a, &b).x);
    }

    #[test]
    fn multiexponentiation_test() {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let mut a: Vec<Field> = Vec::new();
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(5),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(2),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(7),
        });
        a.push(Field {
            pp: params.clone(),
            x: BigInt::from(3),
        });

        let mut G: Vec<Group> = Vec::new();
        G.push(Group {
            pp: params.clone(),
            g: BigInt::from(3),
        });
        G.push(Group {
            pp: params.clone(),
            g: BigInt::from(8),
        });
        G.push(Group {
            pp: params.clone(),
            g: BigInt::from(2),
        });
        G.push(Group {
            pp: params.clone(),
            g: BigInt::from(9),
        });

        let expected = BigInt::mod_mul(&BigInt::from(1451188224), &BigInt::one(), &params.q);

        assert_eq!(expected, multiexponentiation(&G, &a).g)
    }

    #[test]
    fn make_ipp_32() {
        test_helper(32);
    }

    #[test]
    fn make_ipp_16() {
        test_helper(16);
    }
    #[test]
    fn make_ipp_8() {
        test_helper(8);
    }

    #[test]
    fn make_ipp_4() {
        test_helper(4);
    }

    #[test]
    fn make_ipp_2() {
        test_helper(2);
    }

    #[test]
    fn make_ipp_1() {
        test_helper(1);
    }

    /*
    #[test]
    fn make_ipp_32_fast_verify() {
        test_helper_fast_verify(32);
    }

    #[test]
    fn make_ipp_16_fast_verify() {
        test_helper_fast_verify(16);
    }
    #[test]
    fn make_ipp_8_fast_verify() {
        test_helper_fast_verify(8);
    }

    #[test]
    fn make_ipp_4_fast_verify() {
        test_helper_fast_verify(4);
    }

    #[test]
    fn make_ipp_2_fast_verify() {
        test_helper_fast_verify(2);
    }

    #[test]
    fn make_ipp_1_fast_verify() {
        test_helper_fast_verify(1);
    }

    #[test]
    fn make_ipp_non_power_2() {
        // Create random scalar vectors a, b with size non-power of 2
        let n: usize = 9;
        let mut a: Vec<_> = (0..n)
            .map(|_| {
                let rand: FE = ECScalar::new_random();
                rand.to_big_int()
            })
            .collect();

        let mut b: Vec<_> = (0..n)
            .map(|_| {
                let rand: FE = ECScalar::new_random();
                rand.to_big_int()
            })
            .collect();

        // next power of 2
        let _n: usize = n.next_power_of_two();
        let zero_append_vec = vec![BigInt::zero(); _n - n];

        // zero-appending at the end of a, b
        // let mut padded_a = a.clone();
        a.extend_from_slice(&zero_append_vec);

        // let mut padded_b = b.clone();
        b.extend_from_slice(&zero_append_vec);

        test_helper_non_power_2(n, _n, &a, &b);
    }
    */
}
