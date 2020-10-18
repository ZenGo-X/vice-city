#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

pub mod protocols;
pub mod utlities;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum TwoPartyRSAError {
    GeneralError,
    InvalidPaillierKey,
    InvalidElGamalKey,
    InvalidDlogProof,
    InvalidCom,
    CandidateGenerationEncError,
    CandidateGenerationDecError,
    InvalidModProof,
    InvalidEncProof,
    InvalidVerlinProof,
    InvalidPartyOneProduct,
    InvalidElGamalMul,
    BiPrimesNotEqual,
    InvalidDecryption,
    BiPrimalityTestError,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ProofError {
    DlogProofError,
    ElGamalProofError,
    EqError,
    RangeProofError,
    ModProofError,
    DHProofError,
    MulError,
    VerlinError,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum BulletproofError {
    SetupError,
    InnerProductError,
    BPRangeProofError,
}
