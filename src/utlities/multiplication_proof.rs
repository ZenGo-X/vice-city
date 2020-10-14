use crate::utlities::hash;
use crate::utlities::HASH_OUTPUT_BIT_SIZE;
use crate::ProofError;
use curv::arithmetic::traits::{Modulo, Samplable};
use curv::BigInt;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use serde::{Deserialize, Serialize};

/// This proof is a non-interactive version of Multiplication-mod-n^s protocol taken from
/// DJ01 [https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf ]
/// We adjust the protocol for homomorphic Elgamal crypto-system
/// the prover knows 3 plaintexts a,b,c such that ab = c mod q. The prover goal is to prove that a
/// triplet of ciphertexts encrypts plaintexts a,b,c holding the multiplication relationship
/// Witness: {a,b,c,r_a,r_b,r_c}
/// Statement: {e_a, e_b, e_c, pk}
/// protocol:
/// 1) P picks random values d, r_d from Zq,
///    and computes e_d = Enc_pk(d,r_d), e_db = Enc_ek(db, r_d + r_b)
/// 2) using Fiat-Shamir the parties computes a challenge e
/// 3) P sends f = ea + d mod q , z1 = r_a* e + r_d mod q, z2 = r_b *f + (r_db + r_c*e)^-1 mod q
/// 4) V checks:
///     e_a^e * e_d = Enc_ek(f, z1),
///     e_b^f*(e_db*e_c^e)^-1 = Enc_pk(0, z2)

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulProofElGamal {
    pub f: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
    pub e_d: ElGamalCiphertext,
    pub e_db: ElGamalCiphertext,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulWitnessElGamal {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
    pub r_a: BigInt,
    pub r_b: BigInt,
    pub r_c: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulStatementElGamal {
    pub pk: ElGamalPublicKey,
    pub e_a: ElGamalCiphertext,
    pub e_b: ElGamalCiphertext,
    pub e_c: ElGamalCiphertext,
}

impl MulProofElGamal {
    pub fn prove(witness: &MulWitnessElGamal, statement: &MulStatementElGamal) -> Result<Self, ()> {
        let d = BigInt::sample_below(&statement.pk.pp.q);
        let r_d = BigInt::sample_below(&statement.pk.pp.q);
        let e_d =
            ExponentElGamal::encrypt_from_predefined_randomness(&d, &statement.pk, &r_d).unwrap();

        let r_db = BigInt::mod_mul(&r_d, &witness.r_b, &statement.pk.pp.q);
        let db = BigInt::mod_mul(&d, &witness.b, &statement.pk.pp.q);

        let e_db =
            ExponentElGamal::encrypt_from_predefined_randomness(&db, &statement.pk, &r_db).unwrap();

        let e: BigInt = hash(
            &[
                &statement.pk.pp.q,
                &statement.e_a.c1,
                &statement.e_b.c1,
                &statement.e_c.c1,
                &e_d.c1,
                &e_db.c1,
            ],
            &statement.pk.pp,
            HASH_OUTPUT_BIT_SIZE,
        );

        let ea = BigInt::mod_mul(&e, &witness.a, &statement.pk.pp.q);
        let f = BigInt::mod_add(&ea, &d, &statement.pk.pp.q);
        let r_a_e = BigInt::mod_mul(&witness.r_a, &e, &statement.pk.pp.q);
        let z1 = BigInt::mod_add(&r_a_e, &r_d, &statement.pk.pp.q);
        let r_b_f = BigInt::mod_mul(&witness.r_b, &f, &statement.pk.pp.q);
        let r_c_e = BigInt::mod_mul(&witness.r_c, &e, &statement.pk.pp.q);
        let r_db_r_c_e = BigInt::mod_add(&r_db, &r_c_e, &statement.pk.pp.q);
        let z2 = BigInt::mod_sub(&r_b_f, &r_db_r_c_e, &statement.pk.pp.q);

        Ok(MulProofElGamal {
            f,
            z1,
            z2,
            e_d,
            e_db,
        })
    }

    pub fn verify(&self, statement: &MulStatementElGamal) -> Result<(), ProofError> {
        let e: BigInt = hash(
            &[
                &statement.pk.pp.q,
                &statement.e_a.c1,
                &statement.e_b.c1,
                &statement.e_c.c1,
                &self.e_d.c1,
                &self.e_db.c1,
            ],
            &statement.pk.pp,
            HASH_OUTPUT_BIT_SIZE,
        );

        let enc_f_z1 =
            ExponentElGamal::encrypt_from_predefined_randomness(&self.f, &statement.pk, &self.z1)
                .unwrap();
        let enc_0_z2 = ExponentElGamal::encrypt_from_predefined_randomness(
            &BigInt::zero(),
            &statement.pk,
            &self.z2,
        )
        .unwrap();

        let e_a_e = ExponentElGamal::mul(&statement.e_a, &e);
        let e_a_e_e_d = ExponentElGamal::add(&e_a_e, &self.e_d).unwrap();
        let e_c_e = ExponentElGamal::mul(&statement.e_c, &e);
        let e_db_e_c_e = ExponentElGamal::add(&self.e_db, &e_c_e).unwrap();
        let e_db_e_c_e_inv = ExponentElGamal::mul(&e_db_e_c_e, &-BigInt::one());
        let e_b_f = ExponentElGamal::mul(&statement.e_b, &self.f);
        let e_b_f_e_db_e_c_e_inv = ExponentElGamal::add(&e_b_f, &e_db_e_c_e_inv).unwrap();

        match e_a_e_e_d == enc_f_z1 && e_b_f_e_db_e_c_e_inv == enc_0_z2 {
            true => Ok(()),
            false => Err(ProofError::MulError),
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::{Modulo, Samplable};
    use curv::BigInt;

    use crate::utlities::multiplication_proof::MulProofElGamal;
    use crate::utlities::multiplication_proof::MulStatementElGamal;
    use crate::utlities::multiplication_proof::MulWitnessElGamal;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;

    #[test]
    fn test_mul_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let a = BigInt::sample_below(&pp.q);
        let b = BigInt::sample_below(&pp.q);
        let c = BigInt::mod_mul(&a, &b, &pp.q);
        let r_a = BigInt::sample_below(&pp.q);
        let r_b = BigInt::sample_below(&pp.q);
        let r_c = BigInt::sample_below(&pp.q);

        let e_a =
            ExponentElGamal::encrypt_from_predefined_randomness(&a, &keypair.pk, &r_a).unwrap();
        let e_b =
            ExponentElGamal::encrypt_from_predefined_randomness(&b, &keypair.pk, &r_b).unwrap();
        let e_c =
            ExponentElGamal::encrypt_from_predefined_randomness(&c, &keypair.pk, &r_c).unwrap();

        let witness = MulWitnessElGamal {
            a,
            b,
            c,
            r_a,
            r_b,
            r_c,
        };

        let statement = MulStatementElGamal {
            pk: keypair.pk,
            e_a,
            e_b,
            e_c,
        };

        let proof = MulProofElGamal::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_mul_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let a = BigInt::sample_below(&pp.q);
        let b = BigInt::sample_below(&pp.q);
        let c = BigInt::mod_mul(&a, &b, &pp.q) + BigInt::one(); //c != a*b
        let r_a = BigInt::sample_below(&pp.q);
        let r_b = BigInt::sample_below(&pp.q);
        let r_c = BigInt::sample_below(&pp.q);

        let e_a =
            ExponentElGamal::encrypt_from_predefined_randomness(&a, &keypair.pk, &r_a).unwrap();
        let e_b =
            ExponentElGamal::encrypt_from_predefined_randomness(&b, &keypair.pk, &r_b).unwrap();
        let e_c =
            ExponentElGamal::encrypt_from_predefined_randomness(&c, &keypair.pk, &r_c).unwrap();

        let witness = MulWitnessElGamal {
            a,
            b,
            c,
            r_a,
            r_b,
            r_c,
        };

        let statement = MulStatementElGamal {
            pk: keypair.pk,
            e_a,
            e_b,
            e_c,
        };

        let proof = MulProofElGamal::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
}
