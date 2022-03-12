use crate::ProofError;
use bit_vec::BitVec;
use curv::arithmetic::traits::{Converter, Modulo, Samplable};

//use sha2::Sha256;
//use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
//use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
//use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::BigInt;
use curv::arithmetic::BitManipulation;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use rayon::prelude::*;

use crate::utlities::create_hash;

/// This is a non-interactive version of the protocol \pi_eq
/// from https://eprint.iacr.org/2011/494.pdf page 12 point 5.  The witness is {x,r}, the
/// statement is {c, pk, h,h'}. c is an homo-elgamal ciphertext encrypting x with randomness r.
/// h,h' belongs to some other group (not necessarily the elgamal group ) such that h' = h^x.
/// As opposed to the original protocol we assume random oracle model and use Fiat-Shamir. We
/// assume computational security, taking 120 repetitions for enough security :
/// 1) prover computes a vector of random encryptions : c_i = Enc_pk(s_i,r_i).
/// 2) prover computes h'_i = h^s_i
/// 3) using FS: prover computes e = Hash(Vec<h'_i>, Vec<c_i>) and takes first 120bits
/// 4) if e_bit_i = 0 prover outputs z_i = (s_i,r_i),
/// 5) if e_bit_i = 1 prover outputs z_i = (x + s_i, r + r_i)
/// We note that |s_i| = 100 + |x| (same for r_i, r)
/// 6) verifier computes e
/// 7) if e_bit_i = 0 verifer checks c_i = Enc_pk(s_i,r_i) , h'_i = h^s_i
/// 8) if e_bit_i = 1 verifier checks c * c_i = Enc_pk(x + s_i, r + r_i), h'_i * h' = h^(x + s_i)

//TODO: make proof generic for cryptosystem
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqProof {
    pub ciphertext_i_vec: Vec<ElGamalCiphertext>,
    pub h_prime_i_vec: Vec<BigInt>,
    pub z_vec: Vec<Response>,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Response {
    z1: BigInt,
    z2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqWitness {
    pub x: BigInt,
    pub r: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqStatement {
    pub pk: ElGamalPublicKey,
    pub h: BigInt,
    pub h_prime: BigInt,
    pub n: BigInt, // public parameter for h,h' (modulus n)
    pub ciphertext: ElGamalCiphertext,
    pub sec_param: usize,
    pub kapa: usize, // size of random sampled s_i,r_i, must be at least 100
}

impl EqProof {
    pub fn prove(statement: &EqStatement, witness: &EqWitness) -> Result<Self, ProofError> {
        if statement.kapa < 100 {
            return Err(ProofError::EqError);
        }
        let s_i_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|_| BigInt::sample(statement.pk.pp.q.bit_length() + statement.kapa))
            .collect();
        let r_i_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|_| BigInt::sample(statement.pk.pp.q.bit_length() + statement.kapa))
            .collect();

        let h_prime_i_vec = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| BigInt::mod_pow(&statement.h, &s_i_vec[i], &statement.n))
            .collect::<Vec<BigInt>>();

        let ciphertext_i_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| {
                ExponentElGamal::encrypt_from_predefined_randomness(
                    &(s_i_vec[i]).modulus(&statement.pk.pp.q),
                    &statement.pk,
                    &(r_i_vec[i]).modulus(&statement.pk.pp.q),
                )
                .unwrap()
            })
            .collect();

        let mut fs_input = vec![&statement.h, &statement.h_prime];
        for i in 0..statement.sec_param {
            fs_input.push(&h_prime_i_vec[i]);
            fs_input.push(&ciphertext_i_vec[i].c2);
        }
        let e = create_hash(&fs_input);
        let e_bytes_vec = BigInt::to_bytes(&e);
        let bits_of_e = BitVec::from_bytes(&e_bytes_vec[..]);

        let response_vec: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| match bits_of_e[i] {
                false => Response {
                    z1: s_i_vec[i].clone(),
                    z2: r_i_vec[i].clone(),
                },
                true => Response {
                    z1: &witness.x + &s_i_vec[i],
                    z2: &witness.r + &r_i_vec[i],
                },
            })
            .collect();

        Ok(EqProof {
            ciphertext_i_vec,
            h_prime_i_vec,
            z_vec: response_vec,
        })
    }

    pub fn verify(&self, statement: &EqStatement) -> Result<(), ProofError> {
        let mut fs_input = vec![&statement.h, &statement.h_prime];
        for i in 0..statement.sec_param {
            fs_input.push(&self.h_prime_i_vec[i]);
            fs_input.push(&self.ciphertext_i_vec[i].c2);
        }
        let e = create_hash(&fs_input);
        let e_bytes_vec = BigInt::to_bytes(&e);
        let bits_of_e = BitVec::from_bytes(&e_bytes_vec[..]);

        let checks: Vec<_> = (0..statement.sec_param)
            .into_par_iter()
            .map(|i| match bits_of_e[i] {
                false => {
                    ExponentElGamal::encrypt_from_predefined_randomness(
                        &(self.z_vec[i].z1).modulus(&statement.pk.pp.q),
                        &statement.pk,
                        &(self.z_vec[i].z2).modulus(&statement.pk.pp.q),
                    )
                    .unwrap()
                        == self.ciphertext_i_vec[i]
                        && BigInt::mod_pow(&statement.h, &self.z_vec[i].z1, &statement.n)
                            == self.h_prime_i_vec[i]
                }
                true => {
                    let c_star = ExponentElGamal::encrypt_from_predefined_randomness(
                        &(self.z_vec[i].z1).modulus(&statement.pk.pp.q),
                        &statement.pk,
                        &(self.z_vec[i].z2).modulus(&statement.pk.pp.q),
                    )
                    .unwrap();

                    ExponentElGamal::add(&statement.ciphertext, &self.ciphertext_i_vec[i]).unwrap()
                        == c_star
                        && BigInt::mod_pow(&statement.h, &self.z_vec[i].z1, &statement.n)
                            == BigInt::mod_mul(
                                &self.h_prime_i_vec[i],
                                &statement.h_prime,
                                &statement.n,
                            )
                }
            })
            .collect();

        if checks.iter().all(|b| *b) {
            Ok(())
        } else {
            Err(ProofError::EqError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utlities::equal_secret_proof::EqProof;
    use crate::utlities::equal_secret_proof::EqStatement;
    use crate::utlities::equal_secret_proof::EqWitness;
    use curv::arithmetic::traits::{Modulo, Samplable};
    use curv::BigInt;
    use elgamal::prime::is_prime;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;
    use curv::arithmetic::{One, Zero, Integer, BitManipulation};

    #[test]
    fn test_correct_eq_elgamal() {
        let mut p = BigInt::sample(1024);
        let mut q = BigInt::sample(1024);
        while is_prime(&p) != true {
            p = p + BigInt::one();
        }
        while is_prime(&q) != true {
            q = q + BigInt::one();
        }
        let n = p * q;
        let h = BigInt::from(3);
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let x = BigInt::sample_below(&pp.q);
        let r = BigInt::sample_below(&pp.q);
        let h_prime = BigInt::mod_pow(&h, &x, &n);
        let ciphertext =
            ExponentElGamal::encrypt_from_predefined_randomness(&x, &keypair.pk, &r).unwrap();
        let witness = EqWitness { x, r };

        let statement = EqStatement {
            pk: keypair.pk.clone(),
            h,
            h_prime,
            n,
            ciphertext,
            sec_param: 120,
            kapa: 100,
        };

        let proof = EqProof::prove(&statement, &witness).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok())
    }
}
