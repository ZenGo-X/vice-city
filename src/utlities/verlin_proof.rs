use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use curv::arithmetic::Modulo;

use crate::utlities::hash;
use crate::utlities::HASH_OUTPUT_BIT_SIZE;
use crate::ProofError;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use serde::{Deserialize, Serialize};

/// A sigma protocol to allow a prover to demonstrate that a ciphertext c_x has been computed using
/// two other ciphertexts c שמג_cprime, as well as a known value.
/// The proof is taken from https://eprint.iacr.org/2011/494.pdf 3.3.1
/// Witness: {x,x_prime, x_double_prime, r_x}
/// Statement: {c_x, c, c_prime}. The relation is such that:
/// phi_x = c^x * c_prime^x_prime * Enc(x_double_prime, r_x)
/// The protocol:
/// 1) Prover picks random: a,a_prime,a_double_prime and r_a and computes: phi_a
/// 2) prover computes a challenge e using Fiat-Shamir
/// 3) Prover computes  z = xe + a, z' = x'e + a', z_double_prime = x_double_prime*e + a_double_prime
/// and r_z = r_x^e*r_a
/// Verifier accepts if phi_z = phi_x^e * phi_a

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinProofElGamal {
    pub phi_a: ElGamalCiphertext,
    pub z: BigInt,
    pub z_prime: BigInt,
    pub z_double_prime: BigInt,
    pub r_z: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinWitnessElGamal {
    pub x: BigInt,
    pub x_prime: BigInt,
    pub x_double_prime: BigInt,
    pub r_x: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinStatementElGamal {
    pub pk: ElGamalPublicKey,
    pub c: ElGamalCiphertext,
    pub c_prime: ElGamalCiphertext,
    pub phi_x: ElGamalCiphertext,
}

impl VerlinProofElGamal {
    pub fn prove(
        witness: &VerlinWitnessElGamal,
        statement: &VerlinStatementElGamal,
    ) -> Result<Self, ()> {
        let a = BigInt::sample_below(&statement.pk.pp.q);
        let a_prime = BigInt::sample_below(&statement.pk.pp.q);
        let a_double_prime = BigInt::sample_below(&statement.pk.pp.q);
        let r_a = BigInt::sample_below(&statement.pk.pp.q);

        let phi_a = gen_phi(
            &statement.pk,
            &statement.c,
            &statement.c_prime,
            &a,
            &a_prime,
            &a_double_prime,
            &r_a,
        );

        let e: BigInt = hash(
            &[
                &statement.pk.pp.q,
                &statement.c.c1,
                &statement.c_prime.c1,
                &phi_a.c1,
            ],
            &statement.pk.pp.q,
            HASH_OUTPUT_BIT_SIZE,
        );

        let z = (&witness.x * &e + &a).modulus(&statement.pk.pp.q);
        let z_prime = (&witness.x_prime * &e + &a_prime).modulus(&statement.pk.pp.q);
        let z_double_prime =
            (&witness.x_double_prime * &e + &a_double_prime).modulus(&statement.pk.pp.q);
        let r_x_e = (&witness.r_x * &e).modulus(&statement.pk.pp.q);
        let r_z = (&r_x_e + &r_a).modulus(&statement.pk.pp.q);

        Ok(VerlinProofElGamal {
            phi_a,
            z,
            z_prime,
            z_double_prime,
            r_z,
        })
    }

    pub fn verify(&self, statement: &VerlinStatementElGamal) -> Result<(), ProofError> {
        let e: BigInt = hash(
            &[
                &statement.pk.pp.q,
                &statement.c.c1,
                &statement.c_prime.c1,
                &self.phi_a.c1,
            ],
            &statement.pk.pp.q,
            HASH_OUTPUT_BIT_SIZE,
        );
        let phi_x_e = ExponentElGamal::mul(&statement.phi_x, &e);
        let phi_x_e_phi_a = ExponentElGamal::add(&phi_x_e, &self.phi_a).unwrap();

        let phi_z = gen_phi(
            &statement.pk,
            &statement.c,
            &statement.c_prime,
            &self.z,
            &self.z_prime,
            &self.z_double_prime,
            &self.r_z,
        );

        match phi_z == phi_x_e_phi_a {
            true => Ok(()),
            false => Err(ProofError::VerlinError),
        }
    }
}

// helper
fn gen_phi(
    pk: &ElGamalPublicKey,
    c: &ElGamalCiphertext,
    c_prime: &ElGamalCiphertext,
    y: &BigInt,
    y_prime: &BigInt,
    y_double_prime: &BigInt,
    r_y: &BigInt,
) -> ElGamalCiphertext {
    let c_y = ExponentElGamal::mul(c, y);
    let c_prime_y_prime = ExponentElGamal::mul(c_prime, y_prime);

    let c_y_double_prime_r_y =
        ExponentElGamal::encrypt_from_predefined_randomness(y_double_prime, pk, r_y).unwrap();

    let c_y_c_prime_y_prime = ExponentElGamal::add(&c_y, &c_prime_y_prime).unwrap();
    let phi_y = ExponentElGamal::add(&c_y_c_prime_y_prime, &c_y_double_prime_r_y).unwrap();
    phi_y
}

#[cfg(test)]
mod tests {
    use crate::utlities::verlin_proof::gen_phi;
    use crate::utlities::verlin_proof::VerlinProofElGamal;
    use crate::utlities::verlin_proof::VerlinStatementElGamal;
    use crate::utlities::verlin_proof::VerlinWitnessElGamal;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;

    #[test]
    fn test_verlin_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let x = BigInt::sample_below(&pp.q);
        let x_prime = BigInt::sample_below(&pp.q);
        let x_double_prime = BigInt::sample_below(&pp.q);
        let r_x = BigInt::sample_below(&pp.q);

        let c = ExponentElGamal::encrypt(&x, &keypair.pk).unwrap();
        let c_prime = ExponentElGamal::encrypt(&x_prime, &keypair.pk).unwrap();
        let phi_x = gen_phi(
            &keypair.pk,
            &c,
            &c_prime,
            &x,
            &x_prime,
            &x_double_prime,
            &r_x,
        );

        let witness = VerlinWitnessElGamal {
            x,
            x_prime,
            x_double_prime,
            r_x,
        };

        let statement = VerlinStatementElGamal {
            pk: keypair.pk.clone(),
            c,
            c_prime,
            phi_x,
        };

        let proof = VerlinProofElGamal::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_verlin_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let x = BigInt::sample_below(&pp.q);
        let x_prime = BigInt::sample_below(&pp.q);
        let x_double_prime = BigInt::sample_below(&pp.q);
        let r_x = BigInt::sample_below(&pp.q);

        let c = ExponentElGamal::encrypt(&x, &keypair.pk).unwrap();
        let c_prime = ExponentElGamal::encrypt(&x_prime, &keypair.pk).unwrap();
        let phi_x = gen_phi(
            &keypair.pk,
            &c,
            &c_prime,
            &(&x * BigInt::from(2)),
            &x_prime,
            &x_double_prime,
            &r_x,
        );

        let witness = VerlinWitnessElGamal {
            x,
            x_prime,
            x_double_prime,
            r_x,
        };

        let statement = VerlinStatementElGamal {
            pk: keypair.pk.clone(),
            c,
            c_prime,
            phi_x,
        };

        let proof = VerlinProofElGamal::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
}
