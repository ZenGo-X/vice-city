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
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ProofError {
    DlogProofError,
    ElGamalProofError,
    EqError,
    RangeProofError,
    ModProofError,
    DHProofError,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum BulletproofError {
    SetupError,
    InnerProductError,
    RangeProofError,
}