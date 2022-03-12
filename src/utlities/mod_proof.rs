use crate::utlities::range_proof::RangeProof;
use crate::utlities::range_proof::Statement as RangeStatement;
use crate::utlities::range_proof::Witness as RangeWitness;
use crate::ProofError;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::{Converter, Samplable};
use curv::BigInt;
use curv::arithmetic::Integer;
use curv::arithmetic::Zero;
use curv::arithmetic::One;

use std::convert::{TryFrom, TryInto};

use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;

const SECPARAM: usize = 1;
const KAPA: usize = 100;

/// taken from page 13 of [https://eprint.iacr.org/2011/494.pdf] bullet 2:
/// zk proof that a ciphertexts {c,c'} encrypt plaintexts {a, b = a mod p}
/// We define c'' = (c * c'^-1 ) ^ p^(-1). c'' encrypts plaintext d
/// The protocol is composed of two range proofs:
/// 1) b < p
/// 2) d < ceil M/p rounded from above where M is the upper bound on the size of alpha
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ModProof {
    pub range_proof1: RangeProof,
    pub range_proof2: RangeProof,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ModWitness {
    pub r_a: BigInt,
    pub a: BigInt,
    pub r_b: BigInt,
    pub b: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ModStatement {
    pub c: ElGamalCiphertext,
    pub c_prime: ElGamalCiphertext,
    pub modulus_p: BigInt,
    pub upper_bound_m: BigInt, // This is M
    pub pk: ElGamalPublicKey,
}

impl ModProof {
    pub fn prove(witness: &ModWitness, statement: &ModStatement) -> Result<Self, ProofError> {
        let minus_c_prime = ExponentElGamal::mul(&statement.c_prime, &-BigInt::one());
        let c_minus_c_prime = ExponentElGamal::add(&statement.c, &minus_c_prime).unwrap();
        let p_inv = BigInt::mod_inv(&statement.modulus_p, &statement.pk.pp.q);
        if p_inv.is_none() {
            return Err(ProofError::ModProofError);
        }
        let c_double_prime = ExponentElGamal::mul(&c_minus_c_prime, &p_inv.clone().unwrap());

        // TODO: check security / move to tight range proof.
        let range_1 = BigInt::from(3) * &statement.modulus_p; // we compensate for the "slack" in the current range proof.
        let mut range_2 =
            if statement.upper_bound_m.mod_floor(&statement.modulus_p) == BigInt::zero() {
                statement.upper_bound_m.div_floor(&statement.modulus_p)
            } else {
                statement.upper_bound_m.div_floor(&statement.modulus_p) + &statement.modulus_p
            };
        range_2 = range_2 * BigInt::from(3);

        let r_a_mul_minus_r_b = BigInt::mod_sub(&witness.r_a, &witness.r_b, &statement.pk.pp.q);
        let r_d = BigInt::mod_mul(&r_a_mul_minus_r_b, &p_inv.unwrap(), &statement.pk.pp.q);

        let d = (BigInt::mod_sub(&witness.a, &witness.b, &statement.pk.pp.q))
            .div_floor(&statement.modulus_p);

        let range_witness1 = RangeWitness {
            x: witness.b.clone(),
            r: witness.r_b.clone(),
        };
        let range_witness2 = RangeWitness { x: d, r: r_d };
        let range_statement1 = RangeStatement {
            pk: statement.pk.clone(),
            range: range_1,
            ciphertext: statement.c_prime.clone(),
            sec_param: SECPARAM,
            kapa: KAPA,
        };

        let range_statement2 = RangeStatement {
            pk: statement.pk.clone(),
            range: range_2,
            ciphertext: c_double_prime.clone(),
            sec_param: SECPARAM,
            kapa: KAPA,
        };

        let range_proof1 = RangeProof::prove(&range_witness1, &range_statement1);
        let range_proof2 = RangeProof::prove(&range_witness2, &range_statement2);

        match range_proof1.is_ok() && range_proof2.is_ok() {
            true => Ok(ModProof {
                range_proof1: range_proof1.unwrap(),
                range_proof2: range_proof2.unwrap(),
            }),
            false => Err(ProofError::RangeProofError),
        }
    }

    pub fn verify(&self, statement: &ModStatement) -> Result<(), ProofError> {
        let range_1 = BigInt::from(3) * &statement.modulus_p; // we compensate for the "slack" in the current range proof.
        let mut range_2 =
            if statement.upper_bound_m.mod_floor(&statement.modulus_p) == BigInt::zero() {
                statement.upper_bound_m.div_floor(&statement.modulus_p)
            } else {
                statement.upper_bound_m.div_floor(&statement.modulus_p) + &statement.modulus_p
            };
        range_2 = range_2 * BigInt::from(3);

        let minus_c_prime = ExponentElGamal::mul(&statement.c_prime, &-BigInt::one());
        let c_minus_c_prime = ExponentElGamal::add(&statement.c, &minus_c_prime).unwrap();
        let p_inv = BigInt::mod_inv(&statement.modulus_p, &statement.pk.pp.q);
        if p_inv.is_none() {
            return Err(ProofError::ModProofError);
        }
        let c_double_prime = ExponentElGamal::mul(&c_minus_c_prime, &p_inv.unwrap());

        let range_statement1 = RangeStatement {
            pk: statement.pk.clone(),
            range: range_1,
            ciphertext: statement.c_prime.clone(),
            sec_param: SECPARAM,
            kapa: KAPA,
        };

        let range_statement2 = RangeStatement {
            pk: statement.pk.clone(),
            range: range_2,
            ciphertext: c_double_prime.clone(),
            sec_param: SECPARAM,
            kapa: KAPA,
        };

        match self.range_proof1.verify(&range_statement1).is_ok()
            && self.range_proof2.verify(&range_statement2).is_ok()
        {
            true => Ok(()),
            false => Err(ProofError::ModProofError),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::utlities::mod_proof::ModProof;
    use crate::utlities::mod_proof::ModStatement;
    use crate::utlities::mod_proof::ModWitness;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;
    use curv::arithmetic::{One, Zero, Integer, BasicOps};
    use curv::arithmetic::BitManipulation;

    #[test]
    pub fn test_mod_proof() {
        for _ in 1..2 {
            let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
            let keypair = ElGamalKeyPair::generate(&pp);
            let share_bit_size: usize = pp.q.bit_length() / 2 - 2;
            let a = BigInt::sample(share_bit_size);
            let r_a = BigInt::sample_below(&pp.q);
            let modulus_p = BigInt::from(71);
            let b = a.mod_floor(&modulus_p);
            let r_b = BigInt::sample_below(&pp.q);
            let c =
                ExponentElGamal::encrypt_from_predefined_randomness(&a, &keypair.pk, &r_a).unwrap();
            let c_prime =
                ExponentElGamal::encrypt_from_predefined_randomness(&b, &keypair.pk, &r_b).unwrap();
            let witness = ModWitness { r_a, a, r_b, b };
            let statement = ModStatement {
                c,
                c_prime,
                modulus_p,
                upper_bound_m: BigInt::from(2).pow(share_bit_size as u32),
                pk: keypair.pk,
            };

            let proof = ModProof::prove(&witness, &statement).unwrap();
            let verify = proof.verify(&statement);
            assert!(verify.is_ok());
        }
    }
}
