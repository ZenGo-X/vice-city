use curv::BigInt;
use elgamal::ElGamalPP;

pub mod bulletproof;
pub mod inner_product;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pp: ElGamalPP,
    g: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Field {
    pp: ElGamalPP,
    x: BigInt,
}