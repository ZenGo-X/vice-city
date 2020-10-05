use crate::ProofError;
use bit_vec::BitVec;
use curv::arithmetic::traits::{Converter, Modulo, Samplable};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::BigInt;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use rand::prelude::*;
use rayon::prelude::*;
use std::mem;

/// This range proof is adaptation of the range proof given in
/// [https://eprint.iacr.org/2017/552.pdf] appendix A, based on the proof by Boudot in
/// [https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf]
/// We assume random oracle model and adjust the non-interactive proof implemented in
/// [https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/range_proof_ni.rs]
/// to exponent ElGamal cryptosystem. In this proof the verifier is given a ciphertext c=Enc(x) and
/// for a given range q such that x< q/3, the prover convinces the verifier that  0<x<q

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub encrypted_pairs: EncryptedPairs,
    pub z_vec: Vec<Response>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncryptedPairs {
    pub c1: Vec<ElGamalCiphertext>,
    pub c2: Vec<ElGamalCiphertext>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Response {
    Open {
        w1: BigInt,
        r1: BigInt,
        w2: BigInt,
        r2: BigInt,
    },

    Mask {
        j: u8,
        masked_x: BigInt,
        masked_r: BigInt,
    },
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub x: BigInt,
    pub r: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Statement {
    pub pk: ElGamalPublicKey,
    pub range: BigInt,
    pub ciphertext: ElGamalCiphertext,
    pub sec_param: usize,
    pub kapa: usize,
}

impl RangeProof {
    pub fn prove(witness: &Witness, statement: &Statement) -> Result<Self, ProofError> {
        let third_range = statement.range.div_floor(&BigInt::from(3));
        let two_third_range = &third_range * BigInt::from(2);
        let q_minus_1 = &statement.pk.pp.q - BigInt::one();

        let mut w1_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|_| BigInt::sample_range(&third_range, &two_third_range))
            .collect();
        let mut w2_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| &w1_vec[i] - &third_range)
            .collect();

        for i in 0..statement.sec_param {
            if random() {
                mem::swap(&mut w2_vec[i], &mut w1_vec[i]);
            }
        }
        let r1_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|_| BigInt::sample(&statement.pk.pp.q.bit_length() + statement.kapa))
            .collect();
        let r2_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|_| BigInt::sample(&statement.pk.pp.q.bit_length() + statement.kapa))
            .collect();

        let c1_vec: Vec<_> = w1_vec
            .par_iter()
            .zip(&r1_vec)
            .map(|(wi, ri)| {
                ExponentElGamal::encrypt_from_predefined_randomness(
                    &wi,
                    &statement.pk,
                    &ri.modulus(&q_minus_1),
                )
                .unwrap()
            })
            .collect();

        let c2_vec: Vec<_> = w2_vec
            .par_iter()
            .zip(&r2_vec)
            .map(|(wi, ri)| {
                ExponentElGamal::encrypt_from_predefined_randomness(
                    &wi,
                    &statement.pk,
                    &ri.modulus(&q_minus_1),
                )
                .unwrap()
            })
            .collect();

        let mut fs_input = vec![
            &statement.pk.h,
            &statement.ciphertext.c1,
            &statement.ciphertext.c2,
        ];
        for i in 0..statement.sec_param {
            fs_input.push(&c1_vec[i].c1);
            fs_input.push(&c2_vec[i].c1);
        }
        let e = HSha256::create_hash(&fs_input);
        let e_bytes_vec = BigInt::to_vec(&e);
        let bits_of_e = BitVec::from_bytes(&e_bytes_vec[..]);

        let encrypted_pairs = EncryptedPairs {
            c1: c1_vec,
            c2: c2_vec,
        };

        let responses: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                if !ei {
                    Response::Open {
                        w1: w1_vec[i].clone(),
                        r1: r1_vec[i].clone(),
                        w2: w2_vec[i].clone(),
                        r2: r2_vec[i].clone(),
                    }
                } else if &witness.x + &w1_vec[i] > third_range
                    && &witness.x + &w1_vec[i] < two_third_range
                {
                    Response::Mask {
                        j: 1,
                        masked_x: &witness.x + &w1_vec[i],
                        masked_r: BigInt::mod_add(&witness.r, &r1_vec[i], &q_minus_1),
                    }
                } else {
                    Response::Mask {
                        j: 2,
                        masked_x: &witness.x + &w2_vec[i],
                        masked_r: BigInt::mod_add(&witness.r, &r2_vec[i], &q_minus_1),
                    }
                }
            })
            .collect();

        Ok(RangeProof {
            encrypted_pairs,
            z_vec: responses,
        })
    }

    pub fn verify(&self, statement: &Statement) -> Result<(), ProofError> {
        let third_range = statement.range.div_floor(&BigInt::from(3));
        let two_third_range = &third_range * BigInt::from(2);
        let q_minus_1 = &statement.pk.pp.q - BigInt::one();

        let mut fs_input = vec![
            &statement.pk.h,
            &statement.ciphertext.c1,
            &statement.ciphertext.c2,
        ];
        for i in 0..statement.sec_param {
            fs_input.push(&self.encrypted_pairs.c1[i].c1);
            fs_input.push(&self.encrypted_pairs.c2[i].c1);
        }
        let e = HSha256::create_hash(&fs_input);
        let e_bytes_vec = BigInt::to_vec(&e);
        let bits_of_e = BitVec::from_bytes(&e_bytes_vec[..]);

        let verifications: Vec<bool> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                println!("ei: {:?}", ei.clone());
                let response = &self.z_vec[i];
                match (ei, response) {
                    (false, Response::Open { w1, r1, w2, r2 }) => {
                        let mut res = true;

                        let expected_c1i = ExponentElGamal::encrypt_from_predefined_randomness(
                            &w1,
                            &statement.pk,
                            &r1.modulus(&q_minus_1),
                        )
                        .unwrap();
                        let expected_c2i = ExponentElGamal::encrypt_from_predefined_randomness(
                            &w2,
                            &statement.pk,
                            &r2.modulus(&q_minus_1),
                        )
                        .unwrap();

                        if expected_c1i != self.encrypted_pairs.c1[i] {
                            println!("TEST1");

                            res = false;
                        }
                        if expected_c2i != self.encrypted_pairs.c2[i] {
                            println!("TEST2");

                            res = false;
                        }

                        let flag =
                            (w2.le(&third_range) && w1.ge(&third_range) && w1.le(&two_third_range))
                                || (w1.le(&third_range)
                                    && w2.ge(&third_range)
                                    && w2.le(&two_third_range));

                        if !flag {
                            println!("TEST3");
                            res = false;
                        }

                        res
                    }

                    (
                        true,
                        Response::Mask {
                            j,
                            masked_x,
                            masked_r,
                        },
                    ) => {
                        let mut res = true;

                        let c = if *j == 1 {
                            ExponentElGamal::add(&self.encrypted_pairs.c1[i], &statement.ciphertext)
                                .unwrap()
                        } else {
                            ExponentElGamal::add(&self.encrypted_pairs.c2[i], &statement.ciphertext)
                                .unwrap()
                        };

                        let enc_zi = ExponentElGamal::encrypt_from_predefined_randomness(
                            &masked_x,
                            &statement.pk,
                            &masked_r,
                        )
                        .unwrap();
                        if c != enc_zi {
                            res = false;
                        }
                        if *masked_x < third_range || *masked_x > two_third_range {
                            res = false;
                        }

                        res
                    }

                    _ => false,
                }
            })
            .collect();

        if verifications.iter().all(|b| *b) {
            Ok(())
        } else {
            Err(ProofError::RangeProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utlities::range_proof::RangeProof;
    use crate::utlities::range_proof::Statement;
    use crate::utlities::range_proof::Witness;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;

    #[test]
    fn test_range_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let x = BigInt::from(BigInt::from(2).pow(18));
        let r = BigInt::sample_below(&pp.q);
        let ciphertext =
            ExponentElGamal::encrypt_from_predefined_randomness(&x, &keypair.pk, &r).unwrap();
        let range = BigInt::from(BigInt::from(2).pow(20));
        let witness = Witness { x, r };
        let statement = Statement {
            pk: keypair.pk,
            range,
            ciphertext,
            sec_param: 120,
            kapa: 100,
        };

        let proof = RangeProof::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok())
    }

    /// here we use x = q/2>q/3 and therefore proof wll fail
    #[test]
    #[should_panic]
    fn test_bad_range_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let x = BigInt::from(BigInt::from(2).pow(19));
        let r = BigInt::sample_below(&pp.q);
        let ciphertext =
            ExponentElGamal::encrypt_from_predefined_randomness(&x, &keypair.pk, &r).unwrap();
        let range = BigInt::from(BigInt::from(2).pow(20));
        let witness = Witness { x, r };
        let statement = Statement {
            pk: keypair.pk,
            range,
            ciphertext,
            sec_param: 120,
            kapa: 100,
        };

        let proof = RangeProof::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok())
    }
}
