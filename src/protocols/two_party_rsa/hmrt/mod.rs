use crate::utlities::ddh_proof::DDHProof;
use crate::utlities::ddh_proof::DDHStatement;
use crate::utlities::ddh_proof::DDHWitness;
use crate::utlities::ddh_proof::NISigmaProof;
use crate::utlities::hash;
use crate::utlities::jacobi;
use crate::utlities::HASH_OUTPUT_BIT_SIZE;
use crate::utlities::TN;
use curv::BigInt;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalPP;

pub mod party_one;
pub mod party_two;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CiphertextPair {
    pub c0: ElGamalCiphertext,
    pub c1: ElGamalCiphertext,
}

fn gen_ddh_containers(
    x: BigInt,
    g1: &BigInt,
    h1: &BigInt,
    g2: &BigInt,
    h2: &BigInt,
    pp: &ElGamalPP,
) -> (DDHWitness, DDHStatement, DDHProof) {
    let witness = DDHWitness { x };
    let statement = DDHStatement {
        pp: pp.clone(),
        g1: g1.clone(),
        h1: h1.clone(),
        g2: g2.clone(),
        h2: h2.clone(),
    };

    let proof = DDHProof::prove(&witness, &statement);
    (witness, statement, proof)
}

fn compute_randomness_for_biprimality_test(
    n: &BigInt,
    pubkey: &BigInt,
    seed: &BigInt,
) -> (BigInt, TN) {
    let mut gamma = hash(&[n, pubkey, seed], n, HASH_OUTPUT_BIT_SIZE);
    while jacobi(&gamma, n).unwrap() != 1 {
        gamma = hash(&[&gamma], n, HASH_OUTPUT_BIT_SIZE);
    }
    let mut alpha = hash(&[n, pubkey, seed], n, HASH_OUTPUT_BIT_SIZE);
    let mut beta = hash(&[n, pubkey, &alpha], n, HASH_OUTPUT_BIT_SIZE);

    let mut h_cand = TN::new(&alpha, &beta, n);
    while h_cand.is_err() {
        alpha = hash(&[&alpha], n, HASH_OUTPUT_BIT_SIZE);
        beta = hash(&[&alpha], n, HASH_OUTPUT_BIT_SIZE);
        h_cand = TN::new(&alpha, &beta, n);
    }
    let h = h_cand.unwrap();
    (gamma, h)
}




#[cfg(test)]
mod test;

#[cfg(test)]
mod intergration_test;
