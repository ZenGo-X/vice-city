/*

Copyright 2020 by Kzen Networks

Copyright information here.

@license GPL-3.0+ <link>
*/

// based on the paper: https://eprint.iacr.org/2017/1066.pdf

#![allow(non_snake_case)]

// use crate::protocols::bulletproofs::Field;
// use crate::protocols::bulletproofs::Group;
use crate::BulletproofError::{self, BPRangeProofError};
use crate::utlities::inner_product_refined::*;
use elgamal::ElGamalPP;
use curv::arithmetic::traits::{Modulo, Samplable};
use std::ops::{Shl, Shr};
use itertools::iterate;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::BigInt;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub A: BigInt,
    pub S: BigInt,
    pub T1: BigInt,
    pub T2: BigInt,
    pub tau_x: BigInt,
    pub miu: BigInt,
    pub tx: BigInt,
    pub inner_product_proof: IPProof,
}

#[derive(Clone, PartialEq, Debug)]
pub struct BPWitness {
    pub a_vec: Vec<BigInt>,
    pub gamma_vec: Vec<BigInt>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct BPStatement {
    pub g: BigInt,                   // \
    pub h: BigInt,                   // |
    pub u: BigInt,                   // |
    pub g_vec: Vec<BigInt>,          //  > common reference string
    pub h_vec: Vec<BigInt>,          // | 
    pub params: ElGamalPP,           // |
    pub num_bits: usize,             // /
    pub commitments: Vec<BigInt>,    // pedersen commitments
}

pub trait BPRangeProof<T, W, S> {
    fn prove(w: &W, s: &S) -> T;

    fn verify(&self, s: &S) -> Result<(), BulletproofError>;

    fn aggregated_verify(&self, s: &S) -> Result<(), BulletproofError>;

    fn validate_stmt_wit(stmt: &S, wit: &W);

    fn validate_wit(wit: &W);
}

impl BPRangeProof<RangeProof, BPWitness, BPStatement> for RangeProof {
    fn prove(wit: &BPWitness, stmt: &BPStatement) -> RangeProof {
        
        let m = wit.a_vec.len();
        let n = stmt.num_bits;
        let nm = n * m;
        let g = &stmt.g;
        let h = &stmt.h;
        let g_vec = &stmt.g_vec;
        let h_vec = &stmt.h_vec;
        let pp = stmt.params.clone();
        let p = pp.p.clone();
        let q = pp.q.clone();
        let mut secret = wit.a_vec.clone();
        let two = BigInt::from(2);
        let blinding = &wit.gamma_vec;

        // concat all secrets:
        secret.reverse();
        let secret_agg = secret.iter().fold(BigInt::zero(), |acc, x| {
            acc.shl(n) + x
        });

        let aL = (0..nm)
            .map(|i| {
                let shr_secret = secret_agg.clone().shr(i);
                shr_secret.modulus(&two)
            })
            .collect::<Vec<BigInt>>();

        let aR = (0..nm)
            .map(|i| BigInt::mod_sub(&aL[i], &BigInt::one(), &q))
            .collect::<Vec<BigInt>>();

        // compute A
        let alpha = BigInt::sample_below(&q);
        let mut scalars_A = Vec::with_capacity(2 * nm + 1);
        scalars_A.push(alpha.clone());
        scalars_A.extend_from_slice(&aL);
        scalars_A.extend_from_slice(&aR);
        let mut points = Vec::with_capacity(2 * nm + 1);
        points.push((*h).clone());
        points.extend_from_slice(&g_vec);
        points.extend_from_slice(&h_vec);
        let A = multiexponentiation(&points, &scalars_A, &pp, false);

        // compute S
        let sL = (0..nm).map(|_| BigInt::sample_below(&q)).collect::<Vec<BigInt>>();
        let sR = (0..nm).map(|_| BigInt::sample_below(&q)).collect::<Vec<BigInt>>();
        let rho = BigInt::sample_below(&q);
        let mut scalars_S = Vec::with_capacity(2 * nm + 1);
        scalars_S.push(rho.clone());
        scalars_S.extend_from_slice(&sL);
        scalars_S.extend_from_slice(&sR);
        let S = multiexponentiation(&points, &scalars_S, &pp, true);

        // generate challenge y, z
        let y = HSha256::create_hash(&[&A, &S, &BigInt::from(0)]);
        let z = HSha256::create_hash(&[&A, &S, &BigInt::from(1)]);
        let y = y.modulus(&q);
        let z = z.modulus(&q);
        let y_powers = (0..nm)
            .map(|i| {
                BigInt::mod_pow(&y, &BigInt::from(i as u64), &q)
            })
            .collect::<Vec<BigInt>>();
        let two_powers = (0..n)
            .map(|i| {
                BigInt::mod_pow(&two, &BigInt::from(i as u64), &q)
            })
            .collect::<Vec<BigInt>>();     

        // compute t2 such that t(X) = <l(X), r(X)> = t0 + t1.X + t2.X^2
        let t2 = (0..nm)
            .map(|i| {
                let sRi_yi = BigInt::mod_mul(&sR[i], &y_powers[i], &q);
                BigInt::mod_mul(&sRi_yi, &sL[i], &q)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        // compute t1
        let t1 = (0..nm)
            .map(|i| {
                let t1_1 = BigInt::mod_add(&aR[i], &z, &q);
                let t1_2 = BigInt::mod_mul(&t1_1, &y_powers[i], &q);
                let t1_3 = BigInt::mod_mul(&sL[i], &t1_2, &q);
                let t1_4 = BigInt::mod_sub(&aL[i], &z, &q);
                let t1_5 = BigInt::mod_mul(&sR[i], &y_powers[i], &q);
                let t1_6 = BigInt::mod_mul(&t1_4, &t1_5, &q);
                let j = i / n + 2;
                let k = i % n;
                let z_index = BigInt::mod_pow(&z, &BigInt::from(j as u32), &q);
                let two_to_the_i = two_powers[k].clone();
                let t1_7 = BigInt::mod_mul(&z_index, &two_to_the_i, &q);
                let t1_8 = BigInt::mod_mul(&t1_7, &sL[i], &q);
                let t1_6_8 = BigInt::mod_add(&t1_6, &t1_8, &q);
                BigInt::mod_add(&t1_3, &t1_6_8, &q)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        // compute T1, T2
        let tau1 = BigInt::sample_below(&q);
        let tau2 = BigInt::sample_below(&q);
        let T1 = multiexponentiation(&[(*g).clone(), (*h).clone()], &[t1, tau1.clone()], &pp, true);
        let T2 = multiexponentiation(&[(*g).clone(), (*h).clone()], &[t2, tau2.clone()], &pp, true);

        println!("T1 = {:?}", T1);
        println!("T2 = {:?}", T2);

        // generate challenge x
        let x = HSha256::create_hash(&[&A, &S, &T1, &T2]);
        let x = x.modulus(&q);
        let x_sq = BigInt::mod_mul(&x, &x, &q);

        // compute taux and miu
        let taux1 = BigInt::mod_mul(&tau1, &x, &q);
        let taux2 = BigInt::mod_mul(&tau2, &x_sq, &q);
        let taux3 = (0..m)
            .map(|i| {
                let j = BigInt::mod_add(&two, &BigInt::from(i as u32), &q);
                let z_j = BigInt::mod_pow(&z, &j, &q);
                BigInt::mod_mul(&blinding[i], &z_j, &q)
            })
            .fold(taux2, |acc, x| BigInt::mod_add(&acc, &x, &q));
        let tau_x = BigInt::mod_add(&taux1, &taux3, &q);
        let rho_x = BigInt::mod_mul(&rho, &x, &q);
        let miu = BigInt::mod_add(&alpha, &rho_x, &q);

        // compute Lp and Rp
        let Lp = (0..nm)
            .map(|i| {
                let Lp_1 = BigInt::mod_mul(&sL[i], &x, &q);
                let Lp_2 = BigInt::mod_sub(&aL[i], &z, &q);
                BigInt::mod_add(&Lp_1, &Lp_2, &q)
            })
            .collect::<Vec<BigInt>>();

        let Rp = (0..nm)
            .map(|i| {
                let Rp_1 = BigInt::mod_mul(&sR[i], &x, &q);
                let j = i / n + 2;
                let k = i % n;
                let z_index = BigInt::mod_pow(&z, &BigInt::from(j as u32), &q);
                let two_to_the_i = two_powers[k].clone();
                let Rp_2 = BigInt::mod_mul(&z_index, &two_to_the_i, &q);
                let Rp_3 = BigInt::mod_add(&BigInt::mod_add(&z, &aR[i], &q), &Rp_1, &q);
                let Rp_4 = BigInt::mod_mul(&y_powers[i], &Rp_3, &q);
                BigInt::mod_add(&Rp_4, &Rp_2, &q)
            })
            .collect::<Vec<BigInt>>();

        let tx = scalar_inner_product(&Lp, &Rp, &pp, true);

        let hi_tag = (0..nm)
            .map(|i| {
                let yi_inv = BigInt::mod_inv(&y_powers[i], &q);
                BigInt::mod_pow(&h_vec[i], &yi_inv, &p)
            })
            .collect::<Vec<BigInt>>();

        let mut scalars_P = Vec::with_capacity(2 * nm + 1);
        scalars_P.push(tx.clone());
        scalars_P.extend_from_slice(&Lp);
        scalars_P.extend_from_slice(&Rp);
        let P = multiexponentiation(&points, &scalars_P, &pp, true);

        // compute inner product argument
        let ip_stmt = IPStatement {
            u: stmt.u.clone(),
            g_vec: g_vec.to_vec(),
            h_vec: hi_tag,
            params: pp,
            P: P
        };
        let ip_wit = IPWitness {
            a: Lp,
            b: Rp,
        };

        let lg_nm = ((std::mem::size_of_val(&nm) * 8) as usize) - (n.leading_zeros() as usize) - 1;
        let mut L_vec = Vec::with_capacity(lg_nm);
        let mut R_vec = Vec::with_capacity(lg_nm);
        let inner_product_proof = IPProof::prove(&ip_wit, &ip_stmt, &mut L_vec, &mut R_vec);

        RangeProof {
            A,
            S,
            T1,
            T2,
            tau_x,
            miu,
            tx,
            inner_product_proof
        }
    }   

    fn verify(&self, stmt: &BPStatement) -> Result<(), BulletproofError> {
        let m = stmt.commitments.len();
        let n = stmt.num_bits;
        let nm = n * m;
        let g = &stmt.g;
        let h = &stmt.h;
        let u = &stmt.u;
        let g_vec = &stmt.g_vec;
        let h_vec = &stmt.h_vec;
        let pp = stmt.params.clone();
        let p = pp.p.clone();
        let q = pp.q.clone();
        let two = BigInt::from(2);
        let one = BigInt::from(1);

        // regenerate challenges x, y, z
        let y = HSha256::create_hash(&[&self.A, &self.S, &BigInt::from(0)]);
        let z = HSha256::create_hash(&[&self.A, &self.S, &BigInt::from(1)]);
        let x = HSha256::create_hash(&[&self.A, &self.S, &self.T1, &self.T2]);
        let y = y.modulus(&q);
        let x = x.modulus(&q);
        let z = z.modulus(&q);
        let z_minus = BigInt::mod_sub(&q, &z, &q);
        let z_sq = BigInt::mod_mul(&z, &z, &q);
        let x_sq = BigInt::mod_mul(&x, &x, &q);

        // compute delta(y, z)
        let y_powers = (0..nm)
            .map(|i| {
                BigInt::mod_pow(&y, &BigInt::from(i as u64), &q)
            })
            .collect::<Vec<BigInt>>();
        let sum_y_powers = y_powers.iter().fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        let two_powers = (0..n)
            .map(|i| {
                BigInt::mod_pow(&two, &BigInt::from(i as u64), &q)
            })
            .collect::<Vec<BigInt>>();
        let sum_two_powers = two_powers.iter().fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));
        let z_cubed_sum_two_powers = (0..m)
            .map(|i| {
                let j = BigInt::mod_add(&BigInt::from(3), &BigInt::from(i as u64), &q);
                let z_j = BigInt::mod_pow(&z, &j, &q);
                BigInt::mod_mul(&z_j, &sum_two_powers, &q)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        let z_minus_zsq = BigInt::mod_sub(&z, &z_sq, &q);
        let z_minus_zsq_sum_y_powers = BigInt::mod_mul(&z_minus_zsq, &sum_y_powers, &q);
        let delta = BigInt::mod_sub(&z_minus_zsq_sum_y_powers, &z_cubed_sum_two_powers, &q);

        // compute modified generator vector hi_tag
        let hi_tag = (0..nm)
            .map(|i| {
                let yi_inv = BigInt::mod_inv(&y_powers[i], &q);
                BigInt::mod_pow(&h_vec[i], &yi_inv, &p)
            })
            .collect::<Vec<BigInt>>();
        
        // verification check (65)
        let tx_minus_delta = BigInt::mod_sub(&self.tx, &delta, &q);
        let g_tx_minus_delta = BigInt::mod_pow(&g, &tx_minus_delta, &p);
        let h_tau_x = BigInt::mod_pow(&h, &self.tau_x, &p);
        let lhs = BigInt::mod_mul(&g_tx_minus_delta, &h_tau_x, &p);

        let T1_x = BigInt::mod_pow(&self.T1, &x, &p);
        let T2_x = BigInt::mod_pow(&self.T2, &x_sq, &p);
        let T1x_T2x_sq = BigInt::mod_mul(&T1_x, &T2_x, &p);
        let commitments_zm = (0..m)
            .map(|i| {
                let z_2_m = BigInt::mod_pow(&z, &BigInt::from((2 + i) as u64), &q);
                BigInt::mod_pow(&stmt.commitments[i], &z_2_m, &p)
            })
            .collect::<Vec<BigInt>>();
        let commitment_sum = commitments_zm.iter().fold(BigInt::one(), |acc, x| BigInt::mod_mul(&acc, &x, &p));
        let rhs = BigInt::mod_mul(&T1x_T2x_sq, &commitment_sum, &p);

        assert_eq!(lhs, rhs, "first check failed!");

        // compute commitment to Lp and Rp
        let minus_miu = BigInt::mod_sub(&q, &self.miu, &q);
        let scalar_hi_tag = (0..nm)
            .map(|i| {
                let z_yn = BigInt::mod_mul(&z, &y_powers[i], &q);
                let j = i / n;
                let k = i % n;
                let z_j = BigInt::mod_pow(&z, &BigInt::from((2 + j) as u64), &q);
                let z_j_2_n = BigInt::mod_mul(&z_j, &two_powers[k], &q);
                BigInt::mod_add(&z_yn, &z_j_2_n, &q)
            })
            .collect::<Vec<BigInt>>();
        let scalars_g_vec = (0..nm)
            .map(|_| {
                z_minus.clone()
            })
            .collect::<Vec<BigInt>>();

        let mut scalars_P = Vec::with_capacity(2 * nm + 3);
        scalars_P.push(self.tx.clone());
        scalars_P.push(minus_miu);
        scalars_P.push(one.clone());
        scalars_P.push(x.clone());
        scalars_P.extend_from_slice(&scalars_g_vec);
        scalars_P.extend_from_slice(&scalar_hi_tag);
        let mut points_P = Vec::with_capacity(2 * nm + 3);
        points_P.push((*u).clone());
        points_P.push((*h).clone());
        points_P.push(self.A.clone());
        points_P.push(self.S.clone());
        points_P.extend_from_slice(&g_vec);
        points_P.extend_from_slice(&hi_tag);
        let P = multiexponentiation(&points_P, &scalars_P, &pp, true);

        // verify the inner product argument
        let ip_stmt = IPStatement {
            u: stmt.u.clone(),
            g_vec: g_vec.to_vec(),
            h_vec: hi_tag,
            params: pp,
            P: P
        };
        let verify = self.inner_product_proof.verify(&ip_stmt);

        if verify.is_ok() && lhs == rhs {
            Ok(())
        } else {
            Err(BPRangeProofError)
        }
    }

    fn aggregated_verify(&self, stmt: &BPStatement) -> Result<(), BulletproofError> {

        let m = stmt.commitments.len();
        let n = stmt.num_bits;
        let nm = n * m;
        let g = &stmt.g;
        let h = &stmt.h;
        let u = &stmt.u;
        let g_vec = &stmt.g_vec;
        let h_vec = &stmt.h_vec;
        let pp = stmt.params.clone();
        // let p = pp.p.clone();
        let q = pp.q.clone();
        let two = BigInt::from(2);
        let one = BigInt::from(1);
        let lg_nm = self.inner_product_proof.L.len();
        let ped_com = &stmt.commitments;

        // All of the input vectors must have the same length.
        assert_eq!(g_vec.len(), nm);
        assert_eq!(h_vec.len(), nm);
        assert!(nm.is_power_of_two(), "(n*m) must be a power of two!");
        assert!(
            lg_nm <= 64,
            "Not compatible for vector sizes greater than 2^64!"
        );

        // regenerate challenges x, y, z
        let y = HSha256::create_hash(&[&self.A, &self.S, &BigInt::from(0)]);
        let z = HSha256::create_hash(&[&self.A, &self.S, &BigInt::from(1)]);
        let xx = HSha256::create_hash(&[&self.A, &self.S, &self.T1, &self.T2]);
        let y = y.modulus(&q);
        let xx = xx.modulus(&q);
        let z = z.modulus(&q);
        let y_inv = BigInt::mod_inv(&y, &q);
        // let z_minus = BigInt::mod_sub(&q, &z, &q);
        let z_sq = BigInt::mod_mul(&z, &z, &q);
        let xx_sq = BigInt::mod_mul(&xx, &xx, &q);

        // generate a random scalar to combine 2 verification equations
        let c = HSha256::create_hash(&[&self.A, &self.S, &self.T1, &self.T2, &u]);

        // z2_vec = (z^2, z^3, z^4, ..., z^{m+1})
        let z2_vec = iterate(z_sq.clone(), |i| BigInt::mod_mul(&i, &z, &q))
            .take(m)
            .collect::<Vec<BigInt>>();

        // y_vec = (1, y, y^2, ..., y^{nm-1})
        let y_vec = iterate(one.clone(), |i| BigInt::mod_mul(&i, &y, &q))
            .take(nm)
            .collect::<Vec<BigInt>>();

        // sum_y_pow = 1 + y + ... + y^{nm}
        let sum_y_pow = y_vec
            .iter()
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        // vec_2n = (1, 2, 2^2, 2^3, ..., 2^{n})
        let vec_2n = iterate(one.clone(), |i| BigInt::mod_mul(&i, &two, &q))
            .take(n)
            .collect::<Vec<BigInt>>();

        // y_inv_vec = (1, y^{-1}, y^{-2}, ..., y^{-(nm-1)})
        let y_inv_vec = iterate(one.clone(), |i| BigInt::mod_mul(&i, &y_inv, &q))
            .take(nm)
            .collect::<Vec<BigInt>>();

        // d = z^2 d1 + z^3 d2 + ... + z^{m+1} dm
        // where dj = (0^{(j-1)n} || 2^{n} || 0^{(m-j)n}) \in \Z_q^{mn}
        let d = (0..nm)
            .map(|i| {
                let k = i % n;
                let two_i = vec_2n[k].clone();
                let j = i / n;
                let z_j_2 = z2_vec[j].clone();
                BigInt::mod_mul(&two_i, &z_j_2, &q)
            })
            .collect::<Vec<BigInt>>();

        // sum_d = <1^{mn}, d>
        let sum_d = d
            .iter()
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, &q));

        // compute delta(y, z):
        let z_minus_zsq = BigInt::mod_sub(&z, &z_sq, &q);
        let z_minus_zsq_sum_y = BigInt::mod_mul(&z_minus_zsq, &sum_y_pow, &q);
        let sum_d_z = BigInt::mod_mul(&sum_d, &z, &q);
        let delta = BigInt::mod_sub(&z_minus_zsq_sum_y, &sum_d_z, &q);

        // compute sg and sh vectors (unrolling ipp verification)
        let mut x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut minus_x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut minus_x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut allinv = BigInt::one();
        for (Li, Ri) in self
            .inner_product_proof
            .L
            .iter()
            .zip(self.inner_product_proof.R.iter())
        {
            let x = HSha256::create_hash(&[&Li, &Ri, &u]);
            let x = x.modulus(&q);
            let x_inv = BigInt::mod_inv(&x, &q);
            
            let x_sq = BigInt::mod_mul(&x, &x, &q);
            let x_inv_sq = BigInt::mod_mul(&x_inv, &x_inv, &q);

            x_sq_vec.push(x_sq.clone());
            x_inv_sq_vec.push(x_inv_sq.clone());
            minus_x_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_sq, &q));
            minus_x_inv_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_inv_sq, &q));
            allinv = BigInt::mod_mul(&allinv, &x_inv, &q);
        }

        let mut s: Vec<BigInt> = Vec::with_capacity(nm);
        s.push(allinv);
        for i in 1..nm {
            let lg_i =
                (std::mem::size_of_val(&nm) * 8) - 1 - ((i as usize).leading_zeros() as usize);
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [x_k,...,x_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let x_lg_i_sq = x_sq_vec[(lg_nm - 1) - lg_i].clone();
            s.push(s[i - k].clone() * x_lg_i_sq);
        }

        let a_times_s: Vec<BigInt> = (0..nm)
            .map(|i| BigInt::mod_mul(&s[i], &self.inner_product_proof.a_tag, &q))
            .collect();

        let b_times_sinv: Vec<BigInt> = (0..nm)
            .map(|i| {
                let s_inv_i = BigInt::mod_inv(&s[i], &q);
                BigInt::mod_mul(&s_inv_i, &self.inner_product_proof.b_tag, &q)
            })
            .collect();
        
        // exponent of g_vec
        let scalar_g_vec: Vec<BigInt> = (0..nm)
            .map(|i| BigInt::mod_add(&a_times_s[i], &z, &q))
            .collect();

        // exponent of h_vec
        let scalar_h_vec: Vec<BigInt> = (0..nm)
            .map(|i| {
                let b_sinv_plus_di = BigInt::mod_sub(&b_times_sinv[i], &d[i], &q);
                let y_inv_b_sinv_plus_di = BigInt::mod_mul(&y_inv_vec[i], &b_sinv_plus_di, &q);
                BigInt::mod_sub(&y_inv_b_sinv_plus_di, &z, &q)
            })
            .collect();

        // exponent of u
        let ab = BigInt::mod_mul(
            &self.inner_product_proof.a_tag,
            &self.inner_product_proof.b_tag,
            &q,
        );
        let scalar_u = BigInt::mod_sub(&ab, &self.tx, &q);

        // exponent of g
        let delta_minus_tx = BigInt::mod_sub(&delta, &self.tx, &q);
        let scalar_g = BigInt::mod_mul(&c, &delta_minus_tx, &q);

        // exponent of h
        let c_times_taux = BigInt::mod_mul(&c, &self.tau_x, &q);
        let scalar_h = BigInt::mod_sub(&self.miu, &c_times_taux, &q);

        // exponents of A, S
        // let scalar_A = BigInt::mod_sub(&BigInt::zero(), &one, &q);
        let scalar_S = BigInt::mod_sub(&BigInt::zero(), &xx, &q);

        // exponent of L, R
        let scalar_L = minus_x_sq_vec.clone();
        let scalar_R = minus_x_inv_sq_vec.clone();

        // exponents of commitments
        let scalar_coms: Vec<BigInt> = (0..m)
            .map(|i| BigInt::mod_mul(&c, &z2_vec[i], &q))
            .collect();

        // exponents of T_1, T_2
        let scalar_T1 = BigInt::mod_mul(&c, &xx, &q);
        let scalar_T2 = BigInt::mod_mul(&c, &xx_sq, &q);

        // compute concatenated exponent vector
        let mut scalars: Vec<BigInt> = Vec::with_capacity(2 * nm + 2 * lg_nm + m + 6);
        scalars.extend_from_slice(&scalar_g_vec);
        scalars.extend_from_slice(&scalar_h_vec);
        scalars.push(scalar_g);
        scalars.push(scalar_h);
        scalars.push(scalar_u);
        // scalars.push(scalar_A);
        scalars.push(scalar_S);
        scalars.extend_from_slice(&scalar_L);
        scalars.extend_from_slice(&scalar_R);
        scalars.extend_from_slice(&scalar_coms);
        scalars.push(scalar_T1);
        scalars.push(scalar_T2);

        // compute concatenated base vector
        let mut points: Vec<BigInt> = Vec::with_capacity(2 * nm + 2 * lg_nm + m + 6);
        points.extend_from_slice(g_vec);
        points.extend_from_slice(h_vec);
        points.push((*g).clone());
        points.push((*h).clone());
        points.push((*u).clone());
        // points.push(self.A);
        points.push(self.S.clone());
        points.extend_from_slice(&self.inner_product_proof.L);
        points.extend_from_slice(&self.inner_product_proof.R);
        points.extend_from_slice(&ped_com);
        points.push(self.T1.clone());
        points.push(self.T2.clone());

        // single multi-exponentiation check
        let result = multiexponentiation(&points, &scalars, &pp, true);

        if result == self.A {
            Ok(())
        } else {
            Err(BPRangeProofError)
        }
    }

    fn validate_stmt_wit(stmt: &BPStatement, wit: &BPWitness) {
       unimplemented!();
    }

    fn validate_wit(wit: &BPWitness) {
        unimplemented!();
    }
}

#[cfg(test)]
pub mod tests {
    use crate::utlities::bulletproof::*;
    use elgamal::rfc7919_groups::SupportedGroups;

    fn test_helper(n: usize, m: usize, aggregated: bool, out_of_range: bool) {
        let nm = n * m;
        let params = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);

        // generate generators
        let g_vec = (0..nm)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                BigInt::mod_pow(&params.g, &r, &params.p)
            })
            .collect::<Vec<BigInt>>();

        let h_vec = (0..nm)
            .map(|_| {
                let r = BigInt::sample_below(&params.q);
                BigInt::mod_pow(&params.g, &r, &params.p)
            })
            .collect::<Vec<BigInt>>();

        let r = BigInt::sample_below(&params.q);
        let g = BigInt::mod_pow(&params.g, &r, &params.p);

        let r = BigInt::sample_below(&params.q);
        let h = BigInt::mod_pow(&params.g, &r, &params.p);

        let r = BigInt::sample_below(&params.q);
        let u = BigInt::mod_pow(&params.g, &r, &params.p);

        // generate witness vectors
        let range = BigInt::from(2).pow(n as u32);
        let mut v_vec = (0..m)
            .map(|_| BigInt::sample_below(&range))
            .collect::<Vec<BigInt>>();

        if out_of_range {
            let bad_v = BigInt::from(2).pow(n as u32 + 2);
            v_vec[m - 1] = bad_v;
        }

        let r_vec = (0..m).map(|_| BigInt::sample_below(&params.q)).collect::<Vec<BigInt>>();

        // compute pedersen commitments
        let ped_com_vec = (0..m)
            .map(|i| {
                let g_term = BigInt::mod_pow(&g, &v_vec[i], &params.p);
                let h_term = BigInt::mod_pow(&h, &r_vec[i], &params.p);
                BigInt::mod_mul(&g_term, &h_term, &params.p)
            })
            .collect::<Vec<BigInt>>();

        // generate stmt and wit
        let stmt = BPStatement {
            g: g,
            h: h,
            u: u,
            g_vec: g_vec,
            h_vec: h_vec,
            params: params.clone(),
            num_bits: n,
            commitments: ped_com_vec,
        };
        let wit = BPWitness {
            a_vec: v_vec,
            gamma_vec: r_vec,
        };

        let range_proof = RangeProof::prove(&wit, &stmt);
        let mut _verify;
        if aggregated {
            _verify = range_proof.aggregated_verify(&stmt);
        }
        else {
            _verify = range_proof.verify(&stmt);
        } 
        assert!(_verify.is_ok());
    }

    #[test]
    fn test_batch_4_range_proof_32() {
        test_helper(32, 4, false, false)
    }

    #[test]
    #[should_panic]
    fn test_batch_4_range_proof_32_out_of_range() {
        test_helper(32, 4, false, true)
    }

    #[test]
    #[should_panic]
    fn test_agg_4_range_proof_32_out_of_range() {
        test_helper(32, 4, false, true)
    }

    #[test]
    fn test_batch_16_range_proof_64() {
        test_helper(64, 16, false, false)
    }

    #[test]
    fn test_agg_4_range_proof_32() {
        test_helper(32, 4, true, false)
    }

    #[test]
    fn test_agg_16_range_proof_64() {
        test_helper(64, 16, true, false)
    }
}

