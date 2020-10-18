use crate::utlities::hash;
use crate::ProofError;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::traits::ZeroizeBN;
use curv::BigInt;
use elgamal::ElGamalPP;
const HASH_OUTPUT_BIT_SIZE: usize = 256;

///  This is a proof of membership of DDH: (G, xG, yG, xyG)
/// taken from: [ D. Chaum, T. P. Pedersen. Transferred cash grows in size. In Advances in Cryptology, EUROCRYPT ,volume 658 of Lecture Notes in Computer Science, pages 390 - 407, 1993.]
/// The statement is (g1,h1, g2, h2), the witness is x. The relation outputs 1 if :
/// h1 = g1^x, h2 = g2^x
/// The protocol:
/// 1: Prover chooses a1 = g1^s1 , a2 = g2^s for random s
/// 2. prover calculates challenge e = H(g1,h1,g2,h2,a1,a2)
/// 3. prover calculates z  = s + ex,
/// 4. prover sends pi = {e, a1,a2,z}
/// 5. verifier checks that g1^z = a1 * h1^e, g2^z = a2 * h2^e

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DDHProof {
    pub a1: BigInt,
    pub a2: BigInt,
    pub z: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DDHStatement {
    pub pp: ElGamalPP,
    pub g1: BigInt,
    pub h1: BigInt,
    pub g2: BigInt,
    pub h2: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DDHWitness {
    pub x: BigInt,
}

pub trait NISigmaProof<T, W, S> {
    fn prove(w: &W, delta: &S) -> T;

    fn verify(&self, delta: &S) -> Result<(), ProofError>;
}

impl NISigmaProof<DDHProof, DDHWitness, DDHStatement> for DDHProof {
    fn prove(w: &DDHWitness, delta: &DDHStatement) -> DDHProof {
        let mut s = BigInt::sample_below(&delta.pp.q);
        let a1 = BigInt::mod_pow(&delta.g1, &s, &delta.pp.p);
        let a2 = BigInt::mod_pow(&delta.g2, &s, &delta.pp.p);

        let e = hash(
            &[&delta.g1, &delta.g2, &delta.h1, &delta.h2, &a1, &a2],
            &delta.pp.q,
            HASH_OUTPUT_BIT_SIZE,
        );

        let z = &s + &e * &w.x;
        s.zeroize_bn();
        DDHProof { a1, a2, z }
    }

    fn verify(&self, delta: &DDHStatement) -> Result<(), ProofError> {
        let e = hash(
            &[
                &delta.g1, &delta.g2, &delta.h1, &delta.h2, &self.a1, &self.a2,
            ],
            &delta.pp.q,
            HASH_OUTPUT_BIT_SIZE,
        );

        let z = self.z.modulus(&delta.pp.q);
        let g1_z = BigInt::mod_pow(&delta.g1, &z, &delta.pp.p);
        let g2_z = BigInt::mod_pow(&delta.g2, &z, &delta.pp.p);
        let h1_e = BigInt::mod_pow(&delta.h1, &e, &delta.pp.p);
        let h2_e = BigInt::mod_pow(&delta.h2, &e, &delta.pp.p);
        let a1_plus_h1_e = BigInt::mod_mul(&self.a1, &h1_e, &delta.pp.p);
        let a2_plus_h2_e = BigInt::mod_mul(&self.a2, &h2_e, &delta.pp.p);

        if g1_z == a1_plus_h1_e && g2_z == a2_plus_h2_e {
            Ok(())
        } else {
            Err(ProofError::DHProofError)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::utlities::ddh_proof::*;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::ElGamalKeyPair;
    use elgamal::ElGamalPP;
    use elgamal::ExponentElGamal;

    #[test]
    fn test_ddh_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let r = BigInt::sample_below(&pp.q);
        let c =
            ExponentElGamal::encrypt_from_predefined_randomness(&BigInt::zero(), &keypair.pk, &r)
                .unwrap();
        let g1 = pp.g.clone();
        let h1 = c.c1;
        let g2 = keypair.pk.h;
        let h2 = BigInt::mod_pow(&g2, &r, &pp.p);
        let delta = DDHStatement { pp, g1, h1, g2, h2 };
        let w = DDHWitness { x: r };
        let proof = DDHProof::prove(&w, &delta);
        let verify = proof.verify(&delta);
        assert!(verify.is_ok())
    }

    #[test]
    fn test_ddh_proof2() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let r = BigInt::sample_below(&pp.q);
        let c =
            ExponentElGamal::encrypt_from_predefined_randomness(&BigInt::zero(), &keypair.pk, &r)
                .unwrap();
        let g1 = pp.g.clone();
        let g2 = c.c1;
        let h1 = keypair.pk.h;
        let h2 = BigInt::mod_pow(&g2, &keypair.sk.x, &pp.p);
        let delta = DDHStatement { pp, g1, h1, g2, h2 };
        let w = DDHWitness {
            x: keypair.sk.x.clone(),
        };
        let proof = DDHProof::prove(&w, &delta);
        let verify = proof.verify(&delta);
        assert!(verify.is_ok())
    }

    #[test]
    #[should_panic]
    fn test_bad_ddh_proof() {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let r = BigInt::sample_below(&pp.q);
        let c =
            ExponentElGamal::encrypt_from_predefined_randomness(&BigInt::zero(), &keypair.pk, &r)
                .unwrap();
        let g1 = pp.g.clone();
        let h1 = c.c1;
        let g2 = keypair.pk.h;
        // we uuse r' = r+1
        let h2 = BigInt::mod_pow(&g2, &(&r + BigInt::one()), &pp.p);
        let delta = DDHStatement { pp, g1, h1, g2, h2 };
        let w = DDHWitness { x: r };
        let proof = DDHProof::prove(&w, &delta);
        let verify = proof.verify(&delta);
        assert!(verify.is_ok())
    }
}
