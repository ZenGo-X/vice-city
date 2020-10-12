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
use elgamal::ElGamalPP;
use curv::arithmetic::traits::Modulo;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::BigInt;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct IPProof {
    pub L: Vec<BigInt>,
    pub R: Vec<BigInt>,
    pub a_tag: BigInt,
    pub b_tag: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct IPStatement {
    pub u: BigInt,                     // \
    pub g_vec: Vec<BigInt>,            // |
    pub h_vec: Vec<BigInt>,            //  > common reference string
    pub params: ElGamalPP,             // |
    pub P: BigInt,                     // pedersen commitment
}

#[derive(Clone, PartialEq, Debug)]
pub struct IPWitness {
    pub a: Vec<BigInt>,
    pub b: Vec<BigInt>,
}

pub trait InnerProductProof<T, W, S, B> {
    fn prove(w: &W, s: &S, L_vec: &mut Vec<B>, R_vec: &mut Vec<B>) -> T;

    fn verify(&self, s: &S) -> Result<(), BulletproofError>;

    fn validate_stmt_wit(stmt: &S, wit: &W);

    fn validate_proof(&self, stmt: &IPStatement);
}

impl InnerProductProof<IPProof, IPWitness, IPStatement, BigInt> for IPProof {
    fn prove(wit: &IPWitness, stmt: &IPStatement, L_vec: &mut Vec<BigInt>, R_vec: &mut Vec<BigInt>) -> IPProof {

        IPProof::validate_stmt_wit(stmt, wit);

        let G = &stmt.g_vec;
        let H = &stmt.h_vec;
        let P = &stmt.P;
        let u = &stmt.u;
        let a = &wit.a;
        let b = &wit.b;
        let n: usize = G.len();
        let pp = stmt.params.clone();
        let order_f = pp.q.clone();
        let order_g = pp.p.clone();

        // All of the input vectors must have the same length.
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

            let c_L = scalar_inner_product(&a_L, &b_R, &pp, true);
            let c_R = scalar_inner_product(&a_R, &b_L, &pp, true);

            // compute L
            let mut scalars_L: Vec<BigInt> = Vec::with_capacity(2 * n + 1);
            scalars_L.push(c_L);
            scalars_L.extend_from_slice(&a_L);
            scalars_L.extend_from_slice(&b_R);
            let mut points_L: Vec<BigInt> = Vec::with_capacity(2 * n + 1);
            points_L.push(u.clone());
            points_L.extend_from_slice(&G_R);
            points_L.extend_from_slice(&H_L);
            let L = multiexponentiation(&points_L, &scalars_L, &pp, true);
            
            // compute R
            let mut scalars_R: Vec<BigInt> = Vec::with_capacity(2 * n + 1);
            scalars_R.push(c_R);
            scalars_R.extend_from_slice(&a_R);
            scalars_R.extend_from_slice(&b_L);
            let mut points_R: Vec<BigInt> = Vec::with_capacity(2 * n + 1);
            points_R.push(u.clone());
            points_R.extend_from_slice(&G_L);
            points_R.extend_from_slice(&H_R);
            let R = multiexponentiation(&points_R, &scalars_R, &pp, true);
            
            // generate challenge
            let x = HSha256::create_hash(&[&L, &R, &u]);
            let x = x.modulus(&order_f);
            let x_inv = BigInt::mod_inv(&x, &order_f);

            // push L, R
            L_vec.push(L);
            R_vec.push(R);

            // update secret vectors for next round
            let a_new = (0..n)
                .map(|i| {
                    let aLx = BigInt::mod_mul(&a_L[i], &x, &order_f);
                    let aR_minusx = BigInt::mod_mul(&a_R[i], &x_inv, &order_f);
                    BigInt::mod_add(&aLx, &aR_minusx, &order_f)
                })
                .collect::<Vec<BigInt>>();

            let b_new = (0..n)
                .map(|i| {
                    let bRx = BigInt::mod_mul(&b_R[i], &x, &order_f);
                    let bL_minusx = BigInt::mod_mul(&b_L[i], &x_inv, &order_f);
                    BigInt::mod_add(&bRx, &bL_minusx, &order_f)
                })
                .collect::<Vec<BigInt>>();

            // update generator vectors
            let G_new = (0..n)
                .map(|i| {
                    let GLx_inv = BigInt::mod_pow(&G_L[i], &x_inv, &order_g);
                    let GRx = BigInt::mod_pow(&G_R[i], &x, &order_g);
                    BigInt::mod_mul(&GRx, &GLx_inv, &order_g)
                })
                .collect::<Vec<BigInt>>();

            let H_new = (0..n)
                .map(|i| {
                    let HLx = BigInt::mod_pow(&H_L[i], &x, &order_g);
                    let HRx_inv = BigInt::mod_pow(&H_R[i], &x_inv, &order_g);
                    BigInt::mod_mul(&HRx_inv, &HLx, &order_g)
                })
                .collect::<Vec<BigInt>>();

            let stmt_new = IPStatement{
                u: u.clone(), 
                g_vec: G_new, 
                h_vec: H_new, 
                params: pp, 
                P: P.clone()
            };
            let wit_new = IPWitness {
                a: a_new, 
                b: b_new
            };

            return IPProof::prove(&wit_new, &stmt_new, L_vec, R_vec);
        }

        IPProof {
            L: L_vec.to_vec(),
            R: R_vec.to_vec(),
            a_tag: a[0].clone(),
            b_tag: b[0].clone(),
        }
    }

    fn verify(&self, stmt: &IPStatement) -> Result<(), BulletproofError> {
        
        IPProof::validate_proof(self, stmt);

        let G = &stmt.g_vec;
        let H = &stmt.h_vec;
        let n = G.len();
        let pp = stmt.params.clone();
        let order_f = pp.q.clone();
        let order_g = pp.p.clone();
        let P = &stmt.P;
        let u = &stmt.u;

        // All of the input vectors must have the same length.
        assert_eq!(H.len(), n);
        assert!(n.is_power_of_two());

        if n != 1 {
            let n = n / 2;
            let (G_L, G_R) = G.split_at(n);
            let (H_L, H_R) = H.split_at(n);

            // generate challenge
            let x = HSha256::create_hash(&[&self.L[0], &self.R[0], &u]);
            let x = x.modulus(&order_f);
            let x_inv = BigInt::mod_inv(&x, &order_f);
            let x_sq = BigInt::mod_mul(&x, &x, &order_f);
            let x_inv_sq = BigInt::mod_mul(&x_inv, &x_inv, &order_f);

            // update generator vectors
            let G_new = (0..n)
                .map(|i| {
                    let GLx_inv = BigInt::mod_pow(&G_L[i], &x_inv, &order_g);
                    let GRx = BigInt::mod_pow(&G_R[i], &x, &order_g);
                    BigInt::mod_mul(&GRx, &GLx_inv, &order_g)
                })
                .collect::<Vec<BigInt>>();

            let H_new = (0..n)
                .map(|i| {
                    let HLx = BigInt::mod_pow(&H_L[i], &x, &order_g);
                    let HRx_inv = BigInt::mod_pow(&H_R[i], &x_inv, &order_g);
                    BigInt::mod_mul(&HRx_inv, &HLx, &order_g)
                })
                .collect::<Vec<BigInt>>();

            // updating P
            let Lx_sq = BigInt::mod_pow(&self.L[0], &x_sq, &order_g);
            let Rx_inv_sq = BigInt::mod_pow(&self.R[0], &x_inv_sq, &order_g);
            let Lx_Rx_inv = BigInt::mod_mul(&Lx_sq, &Rx_inv_sq, &order_g);
            let P_new = BigInt::mod_mul(&P, &Lx_Rx_inv, &order_g);

            // recursive computation
            let ip = IPProof {
                L: (&self.L[1..]).to_vec(),
                R: (&self.R[1..]).to_vec(),
                a_tag: self.a_tag.clone(),
                b_tag: self.b_tag.clone(),
            };
            let stmt_new = IPStatement {
                u: u.clone(),
                g_vec: G_new,
                h_vec: H_new,
                params: pp,
                P: P_new
            };
            return ip.verify(&stmt_new);
        }

        // final verification check
        let c = BigInt::mod_mul(&self.a_tag, &self.b_tag, &order_f);
        let G_times_a = BigInt::mod_pow(&G[0], &self.a_tag, &order_g);
        let H_times_b = BigInt::mod_pow(&H[0], &self.b_tag, &order_g);
        let Ga_Hb = BigInt::mod_mul(&G_times_a, &H_times_b, &order_g);
        let u_c = BigInt::mod_pow(&u, &c, &order_g);
        let P_calc = BigInt::mod_mul(&Ga_Hb, &u_c, &order_g);

        if P.clone() == P_calc {
            Ok(())
        } else {
            Err(InnerProductError)
        }     
    }

    fn validate_stmt_wit(stmt: &IPStatement, wit: &IPWitness) {
        let p = stmt.params.p.clone();
        let q = stmt.params.q.clone();
        validate_in_group(&[stmt.u.clone()], "u", &p);
        validate_in_group(&stmt.g_vec, "g_vec", &p);
        validate_in_group(&stmt.h_vec, "h_vec", &p);
        validate_in_group(&[stmt.P.clone()], "P", &p);
        validate_in_group(&wit.a, "a", &q);
        validate_in_group(&wit.b, "b", &q);
    }

    fn validate_proof(&self, stmt: &IPStatement) {
        let p = stmt.params.p.clone();
        let q = stmt.params.q.clone();
        validate_in_group(&self.L, "L", &p);
        validate_in_group(&self.R, "R", &p);
        validate_in_group(&[self.a_tag.clone()], "a_tag", &q);
        validate_in_group(&[self.b_tag.clone()], "b_tag", &q);
    }
}


pub fn validate_in_group(input: &[BigInt], tag: &str, order: &BigInt) {
    let k = input.len();
    for i in 0..k {
        let message = format!("Element {}[{}] is invalid!", tag, i);
        assert!(
            input[i] <= *order, 
            message
        );
    }
}

pub fn scalar_inner_product(a: &[BigInt], b: &[BigInt], pp: &ElGamalPP, in_group: bool) -> BigInt {
    assert_eq!(
        a.len(),
        b.len(),
        "inner_product(a,b): lengths of vectors do not match"
    );

    let order = pp.q.clone();
    
    if !in_group {
        validate_in_group(&a, "a", &order);
        validate_in_group(&b, "b", &order);
    }

    let out = BigInt::zero();
    let out = a.iter().zip(b).fold(out, |acc, var| {
        let aibi = BigInt::mod_mul(&(var.0), &(var.1), &order);
        BigInt::mod_add(&acc, &aibi, &order)
    });
    return out;
}

pub fn multiexponentiation(points: &[BigInt], scalars: &[BigInt], pp: &ElGamalPP, in_group: bool) -> BigInt {
    assert_eq!(
        scalars.len(),
        points.len(),
        "multiexponentiation(a,g): lengths of vectors do not match"
    );

    let order = pp.p.clone();

    if !in_group {
        validate_in_group(&scalars, "scalars", &order);
        validate_in_group(&points, "points", &order);
    }

    let out = BigInt::one();
    let out = points.iter().zip(scalars).fold(out, |acc, var| {
        let temp = BigInt::mod_pow(&(var.0), &(var.1), &order);
        BigInt::mod_mul(&acc, &temp, &order)
    });
    return out;
}

#[cfg(test)]
mod tests {
    use crate::utlities::inner_product_refined::*;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalPP;

    fn test_helper(n: usize) {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);

        let g_vec = (0..n)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                BigInt::mod_pow(&params.g, &r, &params.p)
            })
            .collect::<Vec<BigInt>>();

        let h_vec = (0..n)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                BigInt::mod_pow(&params.g, &r, &params.p)
            })
            .collect::<Vec<BigInt>>();

        let r = BigInt::sample_below(&params.q);
        let u = BigInt::mod_pow(&params.g, &r, &params.p);

        let a_vec = (0..n)
            .map(|_| {
                BigInt::sample_below(&params.q)
            })
            .collect::<Vec<BigInt>>();

        let b_vec = (0..n)
            .map(|_| {
                BigInt::sample_below(&params.q)
            })
            .collect::<Vec<BigInt>>();

        let c = scalar_inner_product(&a_vec, &b_vec, &params, true);
        let u_c = BigInt::mod_pow(&u, &c, &params.p);
        let G_pow_a = multiexponentiation(&g_vec, &a_vec, &params, true);
        let H_pow_b = multiexponentiation(&h_vec, &b_vec, &params, true);
        let Ga_Hb = BigInt::mod_mul(&G_pow_a, &H_pow_b, &params.p);
        let P = BigInt::mod_mul(&Ga_Hb, &u_c, &&params.p);

        let stmt = IPStatement {
            u,
            g_vec,
            h_vec,
            params,
            P
        };
        let wit = IPWitness {
            a: a_vec,
            b: b_vec,
        };

        let lg_n = ((std::mem::size_of_val(&n) * 8) as usize) - (n.leading_zeros() as usize) - 1;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        let ipp = IPProof::prove(&wit, &stmt, &mut L_vec, &mut R_vec);
        let ip_verify = ipp.verify(&stmt);
        assert!(ip_verify.is_ok())
    }

    #[test]
    fn scalar_inner_product_test() {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let mut a: Vec<BigInt> = Vec::new();
        let mut b: Vec<BigInt> = Vec::new();
        a.push(BigInt::from(9));
        a.push(BigInt::from(2));
        a.push(BigInt::from(5));
        a.push(BigInt::from(17));
        a.push(BigInt::from(13));
        
        b.push(BigInt::from(19));
        b.push(BigInt::from(3));
        b.push(BigInt::from(6));
        b.push(BigInt::from(12));
        b.push(BigInt::from(7));

        assert_eq!(BigInt::from(502), super::scalar_inner_product(&a, &b, &params, false));
    }

    #[test]
    fn multiexponentiation_test() {
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let mut a: Vec<BigInt> = Vec::new();
        a.push(BigInt::from(5));
        a.push(BigInt::from(2));
        a.push(BigInt::from(7));
        a.push(BigInt::from(3));

        let mut G: Vec<BigInt> = Vec::new();
        G.push(BigInt::from(3));
        G.push(BigInt::from(8));
        G.push(BigInt::from(2));
        G.push(BigInt::from(9));

        let expected = BigInt::mod_mul(&BigInt::from(1451188224), &BigInt::one(), &params.p);

        assert_eq!(expected, super::multiexponentiation(&G, &a, &params, false));
    }

    #[test]
    fn make_ipp_1() {
        test_helper(1)
    }

    #[test]
    fn make_ipp_2() {
        test_helper(2)
    }

    #[test]
    fn make_ipp_4() {
        test_helper(4)
    }

    #[test]
    fn make_ipp_8() {
        test_helper(8)
    }

    #[test]
    fn make_ipp_64() {
        test_helper(64)
    }
}