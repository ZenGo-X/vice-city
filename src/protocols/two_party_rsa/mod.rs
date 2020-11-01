pub mod hmrt;

// for N with 2048 bits
pub const PAILLIER_MODULUS: usize = 3072;
pub const CANDIDATE_BIT_LENGTH: usize = 2048;
const SEC_PARAM: usize = 1;

// testing : for N with 128 bit
//const PAILLIER_MODULUS: usize = 2048;
//pub const CANDIDATE_BIT_LENGTH: usize = 128;
//const SEC_PARAM: usize = 1;
