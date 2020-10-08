use crate::utlities::ddh_proof::DDHProof;
use crate::utlities::ddh_proof::DDHStatement;
use crate::utlities::ddh_proof::DDHWitness;
use crate::utlities::ddh_proof::NISigmaProof;
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

#[cfg(test)]
mod test;
