use crate::utlities::hash;
use crate::ProofError;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::ZeroizeBN;
use curv::BigInt;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPublicKey;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// forms a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// The implementation was adapted to cyclic group of prime order from:
/// https://github.com/ZenGo-X/curv/blob/master/src/cryptographic_primitives/proofs/sigma_correct_homomorphic_elgamal_enc.rs
/// Specifically, the witness is ω = (x, r), the statement is δ = (g, h, c1, c2).
/// The relation R outputs 1 if c1 = g^y, c2 = g^m * h^y
/// proof goes as follows:
/// 1. The prover chooses s1, s2, computes a1 = g^s1, a2 = h^s2, a3 = g^s2 and sends to the verifier t = a1 * a2, a3
/// 2. The verifier picks a challenge e \in Z_q
/// 3. The proveer computes z1 = s1 + e*x and  z2 = s2 + e*r
/// 4. The verifier accepes if g^z1 * h^z2 = t * c2^e and g^z2 = a3 * c1*e

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalProof {
    pub t: BigInt,
    pub a3: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalWitness {
    pub r: BigInt,
    pub m: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalStatement {
    pub pk: ElGamalPublicKey,
    pub ciphertext: ElGamalCiphertext,
}

impl HomoELGamalProof {
    pub fn prove(w: &HomoElGamalWitness, delta: &HomoElGamalStatement) -> HomoELGamalProof {
        let mut s1 = BigInt::sample_below(&delta.pk.pp.q);
        let mut s2 = BigInt::sample_below(&delta.pk.pp.q);
        let mut a1 = BigInt::mod_pow(&delta.pk.pp.g, &s1, &delta.pk.pp.p);
        let mut a2 = BigInt::mod_pow(&delta.pk.h, &s2, &delta.pk.pp.p);
        let a3 = BigInt::mod_pow(&delta.pk.pp.g, &s2, &delta.pk.pp.p);
        let t = BigInt::mod_mul(&a1, &a2, &delta.pk.pp.p);
        let e = hash(
            &[
                &t,
                &a3,
                &delta.pk.pp.g,
                &delta.pk.h,
                &delta.ciphertext.c1,
                &delta.ciphertext.c2,
            ],
            &delta.pk.pp,
            256, // TODO
        );

        let z1 = &s1 + &w.m * &e;
        let z2 = &s2 + &w.r * &e;

        s1.zeroize_bn();
        s2.zeroize_bn();
        a1.zeroize_bn();
        a2.zeroize_bn();
        HomoELGamalProof { t, a3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement) -> Result<(), ProofError> {
        let e = hash(
            &[
                &self.t,
                &self.a3,
                &delta.pk.pp.g,
                &delta.pk.h,
                &delta.ciphertext.c1,
                &delta.ciphertext.c2,
            ],
            &delta.pk.pp,
            256,
        );

        let g_z1 = BigInt::mod_pow(&delta.pk.pp.g, &self.z1, &delta.pk.pp.p);
        let h_z2 = BigInt::mod_pow(&delta.pk.h, &self.z2, &delta.pk.pp.p);

        let g_z1_mul_h_z2 = BigInt::mod_mul(&g_z1, &h_z2, &delta.pk.pp.p);
        let c1_e = BigInt::mod_pow(&delta.ciphertext.c1, &e, &delta.pk.pp.p);
        let c2_e = BigInt::mod_pow(&delta.ciphertext.c2, &e, &delta.pk.pp.p);

        let t_c2_e = BigInt::mod_mul(&self.t, &c2_e, &delta.pk.pp.p);
        let g_z2 = BigInt::mod_pow(&delta.pk.pp.g, &self.z2, &delta.pk.pp.p);
        let a3_c1_e = BigInt::mod_mul(&self.a3, &c1_e, &delta.pk.pp.p);

        if g_z1_mul_h_z2 == t_c2_e && g_z2 == a3_c1_e {
            Ok(())
        } else {
            Err(ProofError::ElGamalProofError)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::utlities::elgamal_enc_proof::*;
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;

    #[test]
    fn test_correct_homo_elgamal() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let m = BigInt::from(11);
        let r = BigInt::sample_below(&pp.q);
        let c = ExponentElGamal::encrypt_from_predefined_randomness(&m, &keypair.pk, &r).unwrap();
        let delta = HomoElGamalStatement {
            pk: keypair.pk,
            ciphertext: c,
        };
        let w = HomoElGamalWitness { r, m };
        let proof = HomoELGamalProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok())
    }
}
