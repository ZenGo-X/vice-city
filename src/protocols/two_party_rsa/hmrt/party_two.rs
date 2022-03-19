use crate::protocols::two_party_rsa::hmrt::compute_randomness_for_biprimality_test;
use crate::protocols::two_party_rsa::hmrt::gen_ddh_containers;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneBiPrimalityTest;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationFirstMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationFirstMsgSemiHonest;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationSecondMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationSecondMsgSemiHonest;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationThirdMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGenerationThirdMsgSemiHonest;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneComputeProductFirstMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneComputeProductSecondMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneElgamalProductFirstMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneElgamalProductSecondMsg;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneKeySetupFirstMsg as KeySetupFirstMsgPartyOne;
use crate::protocols::two_party_rsa::hmrt::CiphertextPair;
use crate::protocols::two_party_rsa::CANDIDATE_BIT_LENGTH;
use crate::protocols::two_party_rsa::PAILLIER_MODULUS;
use crate::protocols::two_party_rsa::SEC_PARAM;
use crate::utlities::ddh_proof::DDHProof;
use crate::utlities::ddh_proof::DDHStatement;
use crate::utlities::ddh_proof::DDHWitness;
use crate::utlities::ddh_proof::NISigmaProof;
use crate::utlities::dlog_proof::DLogProof;
use crate::utlities::dlog_proof::ProveDLog;
use crate::utlities::dlog_proof::Statement as DLogStatement;
use crate::utlities::dlog_proof::Witness as DLogWitness;
use crate::utlities::elgamal_enc_proof::HomoELGamalProof;
use crate::utlities::elgamal_enc_proof::HomoElGamalStatement;
use crate::utlities::elgamal_enc_proof::HomoElGamalWitness;
use crate::utlities::equal_secret_proof::EqProof;
use crate::utlities::equal_secret_proof::EqStatement;
use crate::utlities::equal_secret_proof::EqWitness;
use crate::utlities::equal_secret_proof_tn::EqProofTN;
use crate::utlities::equal_secret_proof_tn::EqStatementTN;
use crate::utlities::equal_secret_proof_tn::EqWitnessTN;
use crate::utlities::mod_proof::ModProof;
use crate::utlities::mod_proof::ModStatement;
use crate::utlities::mod_proof::ModWitness;
use crate::utlities::multiplication_proof::MulProofElGamal;
use crate::utlities::multiplication_proof::MulStatementElGamal;
use crate::utlities::multiplication_proof::MulWitnessElGamal;
use crate::utlities::range_proof::RangeProof;
use crate::utlities::range_proof::Statement as BoundStatement;
use crate::utlities::range_proof::Witness as BoundWitness;
use crate::utlities::verlin_proof::VerlinProofElGamal;
use crate::utlities::verlin_proof::VerlinStatementElGamal;
use crate::utlities::verlin_proof::VerlinWitnessElGamal;
use crate::utlities::TN;
use crate::TwoPartyRSAError;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use curv::arithmetic::{One, Zero, Integer};
use curv::arithmetic::BasicOps;
use elgamal::rfc7919_groups::SupportedGroups;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalKeyPair;
use elgamal::ElGamalPP;
use elgamal::ElGamalPrivateKey;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use paillier::core::Randomness;
use paillier::traits::KeyGeneration;
use paillier::traits::{Add, Mul};
use paillier::DecryptionKey;
use paillier::EncryptWithChosenRandomness;
use paillier::EncryptionKey;
use paillier::Paillier;
use paillier::{RawCiphertext, RawPlaintext};
use zk_paillier::zkproofs::CiphertextStatement;
use zk_paillier::zkproofs::MulStatement;
use zk_paillier::zkproofs::NiCorrectKeyProof;
use zk_paillier::zkproofs::ZeroStatement;
use zk_paillier::zkproofs::SALT_STRING;
use zk_paillier::zkproofs::{VerlinProof, VerlinStatement, VerlinWitness};

//TODO: add zeroize if needed
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoKeySetup {
    pub local_paillier_pubkey: EncryptionKey,
    pub local_elgamal_pubkey: ElGamalPublicKey,
    pub remote_paillier_pubkey: EncryptionKey,
    pub remote_elgamal_pubkey: ElGamalPublicKey,
    pub joint_elgamal_pubkey: ElGamalPublicKey,
    private: PartyTwoPrivate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySetupFirstMsg {
    pub ek: EncryptionKey,
    pub pk: ElGamalPublicKey,
    pub correct_key_proof: NiCorrectKeyProof,
    pub dlog_proof: DLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoPrivate {
    dk: DecryptionKey,
    sk: ElGamalPrivateKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationSemiHonest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationFirstMsgSemiHonest {
    pub c_i: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationSecondMsgSemiHonest {
    pub c_1_alpha: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationThirdMsgSemiHonest {
    pub c_alpha_random: ElGamalCiphertext,
    pub c_alpha_tilde_random: ElGamalCiphertext,
    pub partial_dec_c_alpha: BigInt,
    pub partial_dec_c_alpha_tilde: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGeneration {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationFirstMsg {
    pub c_i: ElGamalCiphertext,
    pub pi_enc: HomoELGamalProof,
    pub pi_bound: RangeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationSecondMsg {
    pub pi_mod: ModProof,
    pub c_1_alpha: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateGenerationThirdMsg {
    pub proof_alpha: DDHProof,
    pub proof_alpha_tilde: DDHProof,
    pub c_alpha_random: ElGamalCiphertext,
    pub c_alpha_tilde_random: ElGamalCiphertext,
    pub partial_dec_c_alpha: BigInt,
    pub partial_dec_c_alpha_tilde: BigInt,
    pub ddh_proof_alpha: DDHProof,
    pub ddh_proof_alpha_tilde: DDHProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoCandidateWitness {
    pub p_1: BigInt,
    pub r_1: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoComputeProduct {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoComputeProductFirstMsg {
    pub c_n_p0_q0: BigInt,
    pub pi_verlin: VerlinProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoElgamalProductFirstMsg {
    pub c_p1q1: ElGamalCiphertext,
    pub mul_proof_eg: MulProofElGamal,
    pub c_p0q1_q0p1_p1q1: ElGamalCiphertext,
    pub verlin_proof: VerlinProofElGamal,
    pub c_n_1_sk2: BigInt,
    pub ddh_proof: DDHProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyTwoBiPrimalityTest {
    pub gamma_1: BigInt,
    pub u2: TN,
    pub eq_proof: EqProof,
    pub eq_proof_tn: EqProofTN,
}

impl PartyTwoKeySetup {
    pub fn gen_local_keys_and_first_message_to_party_one() -> (KeySetupFirstMsg, PartyTwoPrivate) {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let witness = DLogWitness {
            x: keypair.sk.x.clone(),
        };
        let dlog_proof = DLogProof::prove(&witness, &pp);

        let (ek_new, dk_new) = Paillier::keypair_with_modulus_size(PAILLIER_MODULUS).keys();
        let correct_key_proof = NiCorrectKeyProof::proof(&dk_new, None);

        let party_two_private = PartyTwoPrivate {
            dk: dk_new,
            sk: keypair.sk,
        };
        (
            KeySetupFirstMsg {
                ek: ek_new,
                pk: keypair.pk.clone(),
                correct_key_proof,
                dlog_proof,
            },
            party_two_private,
        )
    }

    pub fn verify_party_one_first_message_and_output_party_two_keys(
        party_one_first_message: &KeySetupFirstMsgPartyOne,
        party_two_first_message: &KeySetupFirstMsg,
        party_two_private: PartyTwoPrivate,
    ) -> Result<Self, TwoPartyRSAError> {
        let dlog_statement = DLogStatement {
            h: party_one_first_message.pk.h.clone(),
        };

        match party_one_first_message
            .dlog_proof
            .verify(&dlog_statement, &party_two_first_message.pk.pp)
        {
            Ok(()) => {
                match party_one_first_message
                    .correct_key_proof
                    .verify(&party_one_first_message.ek, SALT_STRING)
                {
                    Ok(()) => Ok(PartyTwoKeySetup {
                        local_paillier_pubkey: party_two_first_message.ek.clone(),
                        local_elgamal_pubkey: party_two_first_message.pk.clone(),
                        remote_paillier_pubkey: party_one_first_message.ek.clone(),
                        remote_elgamal_pubkey: party_one_first_message.pk.clone(),
                        joint_elgamal_pubkey: party_two_first_message
                            .pk
                            .add(&party_one_first_message.pk)
                            .unwrap(),
                        private: party_two_private,
                    }),
                    Err(_) => Err(TwoPartyRSAError::InvalidPaillierKey),
                }
            }
            Err(_) => Err(TwoPartyRSAError::InvalidElGamalKey),
        }
    }
}

impl PartyTwoCandidateGeneration {
    pub fn generate_shares_of_candidate(
        keys: &PartyTwoKeySetup,
    ) -> (
        PartyTwoCandidateWitness,
        PartyTwoCandidateGenerationFirstMsg,
    ) {
        let share_bit_size: usize = CANDIDATE_BIT_LENGTH / 2 - 2 ;
        let p_i = BigInt::sample(share_bit_size);
        let r_i = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_i = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_i,
            &keys.joint_elgamal_pubkey,
            &r_i,
        )
        .unwrap();
        let enc_witness = HomoElGamalWitness {
            r: r_i.clone(),
            m: p_i.clone(),
        };
        let enc_statement = HomoElGamalStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            ciphertext: c_i.clone(),
        };
        let bound_witness = BoundWitness {
            x: p_i.clone(),
            r: r_i.clone(),
        };
        let bound_statement = BoundStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            // TODO: in current range proof this will give some slack such that it is possible that
            // a prover chose 2^(N/2-2)<x< 1/3 * 2^(N/2).
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: c_i.clone(),
            sec_param: SEC_PARAM,
            kapa: 100, //TODO : parameterize
        };

        let enc_proof = HomoELGamalProof::prove(&enc_witness, &enc_statement);
        let bound_proof = RangeProof::prove(&bound_witness, &bound_statement).unwrap(); // TODO: handle error properly

        (
            PartyTwoCandidateWitness { p_1: p_i, r_1: r_i },
            PartyTwoCandidateGenerationFirstMsg {
                c_i,
                pi_enc: enc_proof,
                pi_bound: bound_proof,
            },
        )
    }

    pub fn generate_shares_of_candidate_inject(
        keys: &PartyTwoKeySetup,
        prime_share: BigInt,
    ) -> (
        PartyTwoCandidateWitness,
        PartyTwoCandidateGenerationFirstMsg,
    ) {
        let p_i = prime_share;
        let r_i = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_i = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_i,
            &keys.joint_elgamal_pubkey,
            &r_i,
        )
        .unwrap();
        let enc_witness = HomoElGamalWitness {
            r: r_i.clone(),
            m: p_i.clone(),
        };
        let enc_statement = HomoElGamalStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            ciphertext: c_i.clone(),
        };
        let bound_witness = BoundWitness {
            x: p_i.clone(),
            r: r_i.clone(),
        };
        let bound_statement = BoundStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            // TODO: in current range proof this will give some slack such that it is possible that
            // a prover chose 2^(N/2-2)<x< 1/3 * 2^(N/2).
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: c_i.clone(),
            sec_param: SEC_PARAM,
            kapa: 100, //TODO : parameterize
        };

        let enc_proof = HomoELGamalProof::prove(&enc_witness, &enc_statement);
        let bound_proof = RangeProof::prove(&bound_witness, &bound_statement).unwrap(); // TODO: handle error properly

        (
            PartyTwoCandidateWitness { p_1: p_i, r_1: r_i },
            PartyTwoCandidateGenerationFirstMsg {
                c_i,
                pi_enc: enc_proof,
                pi_bound: bound_proof,
            },
        )
    }

    pub fn verify_party_one_first_message_and_normalize_ciphertexts(
        keys: &PartyTwoKeySetup,
        party_one_first_message: &PartyOneCandidateGenerationFirstMsg,
        party_two_first_message: &PartyTwoCandidateGenerationFirstMsg,
    ) -> Result<CiphertextPair, TwoPartyRSAError> {
        let enc_statement = HomoElGamalStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            ciphertext: party_one_first_message.c_i.clone(),
        };

        let bound_statement = BoundStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: party_one_first_message.c_i.clone(),
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        match party_one_first_message
            .pi_enc
            .verify(&enc_statement)
            .is_ok()
            && party_one_first_message
                .pi_bound
                .verify(&bound_statement)
                .is_ok()
        {
            true => {
                let c_party_one_mul_4 =
                    ExponentElGamal::mul(&party_one_first_message.c_i, &BigInt::from(4));
                let c_party_two_mul_4 =
                    ExponentElGamal::mul(&party_two_first_message.c_i, &BigInt::from(4));
                Ok(CiphertextPair {
                    c0: ExponentElGamal::add(
                        &c_party_one_mul_4,
                        &ExponentElGamal::encrypt_from_predefined_randomness(
                            &BigInt::from(3),
                            &keys.joint_elgamal_pubkey,
                            &BigInt::zero(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    c1: c_party_two_mul_4,
                })
            }
            false => Err(TwoPartyRSAError::CandidateGenerationEncError),
        }
    }

    pub fn trial_division_prepare_c_alpha(
        alpha: &BigInt,
        keys: &PartyTwoKeySetup,
        c: &CiphertextPair,
        w: &PartyTwoCandidateWitness,
    ) -> Result<PartyTwoCandidateGenerationSecondMsg, TwoPartyRSAError> {
        // update witness:
        let p_1 = BigInt::mod_mul(&w.p_1, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q);
        let r_1 = BigInt::mod_mul(&w.r_1, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q);

        let p_1_mod_alpha = p_1.mod_floor(alpha);
        let r_1_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let c_1_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_1_mod_alpha,
            &keys.joint_elgamal_pubkey,
            &r_1_alpha,
        )
        .unwrap();

        let mod_statement = ModStatement {
            c: c.c1.clone(),
            c_prime: c_1_alpha.clone(),
            modulus_p: alpha.clone(),
            upper_bound_m: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32), // n/2 instead of n/2-2 as is written in the paper : we suspect paper has a typo and do not consider the fact that ciphertexts and plaintext are scaled by mul4
            pk: keys.joint_elgamal_pubkey.clone(),
        };

        let mod_witness = ModWitness {
            r_a: r_1,
            a: p_1,
            r_b: r_1_alpha,
            b: p_1_mod_alpha,
        };

        let proof = ModProof::prove(&mod_witness, &mod_statement);

        match proof {
            Ok(_) => Ok(PartyTwoCandidateGenerationSecondMsg {
                pi_mod: proof.unwrap(),
                c_1_alpha,
            }),
            Err(_) => Err(TwoPartyRSAError::InvalidModProof),
        }
    }

    pub fn verify_party_one_second_message_and_partial_decrypt(
        party_one_second_message: &PartyOneCandidateGenerationSecondMsg,
        party_two_second_message: &PartyTwoCandidateGenerationSecondMsg,
        alpha: &BigInt,
        keys: &PartyTwoKeySetup,
        c: &CiphertextPair,
    ) -> Result<
        (
            PartyTwoCandidateGenerationThirdMsg,
            ElGamalCiphertext,
            ElGamalCiphertext,
        ),
        TwoPartyRSAError,
    > {
        let mod_statement = ModStatement {
            c: c.c0.clone(),
            c_prime: party_one_second_message.c_0_alpha.clone(),
            modulus_p: alpha.clone(),
            upper_bound_m: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            pk: keys.joint_elgamal_pubkey.clone(),
        };
        let verify = party_one_second_message.pi_mod.verify(&mod_statement);
        if verify.is_err() {
            return Err(TwoPartyRSAError::InvalidModProof);
        };
        let c_alpha = ExponentElGamal::add(
            &party_one_second_message.c_0_alpha,
            &party_two_second_message.c_1_alpha,
        )
        .unwrap();
        // Enc(-alpha) is known to both parties therefore we use a predefined randomness known to both (r = 2)
        let enc_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            alpha,
            &keys.joint_elgamal_pubkey,
            &BigInt::from(2),
        )
        .unwrap();
        //let enc_minus_alpha = ExponentElGamal::mul(&enc_alpha, &(-BigInt::one()));
        let enc_minus_alpha = crate::utlities::mul_neg_one(&enc_alpha);
        let c_alpha_tilde = ExponentElGamal::add(&c_alpha, &enc_minus_alpha).unwrap();

        // we raise each ciphertext with a secret random number
        let r_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let r_alpha_tilde = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_alpha_random = ExponentElGamal::mul(&c_alpha, &r_alpha);
        let c_alpha_tilde_random = ExponentElGamal::mul(&c_alpha_tilde, &r_alpha_tilde);

        // we use proof of DDH to prove to counter party that c_alpha_random = c_alpha ^r and same for c_alpha_tilde
        let (_, _, ddh_proof_alpha) = gen_ddh_containers(
            r_alpha,
            &c_alpha.c1,
            &c_alpha_random.c1,
            &c_alpha.c2,
            &c_alpha_random.c2,
            &keys.joint_elgamal_pubkey.pp,
        );

        let (_, _, ddh_proof_alpha_tilde) = gen_ddh_containers(
            r_alpha_tilde,
            &c_alpha_tilde.c1,
            &c_alpha_tilde_random.c1,
            &c_alpha_tilde.c2,
            &c_alpha_tilde_random.c2,
            &keys.joint_elgamal_pubkey.pp,
        );

        let dec_key_alpha = BigInt::mod_pow(
            &c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        let statement_alpha = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.local_elgamal_pubkey.h.clone(),
            g2: c_alpha_random.c1.clone(),
            h2: dec_key_alpha.clone(),
        };
        let witness_alpha = DDHWitness {
            x: keys.private.sk.x.clone(),
        };
        let statement_alpha_tilde = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.local_elgamal_pubkey.h.clone(),
            g2: c_alpha_tilde_random.c1.clone(),
            h2: dec_key_alpha_tilde.clone(),
        };

        let proof_alpha = DDHProof::prove(&witness_alpha, &statement_alpha);
        let proof_alpha_tilde = DDHProof::prove(&witness_alpha, &statement_alpha_tilde);

        Ok((
            PartyTwoCandidateGenerationThirdMsg {
                proof_alpha,
                proof_alpha_tilde,
                c_alpha_random,
                c_alpha_tilde_random,
                partial_dec_c_alpha: dec_key_alpha,
                partial_dec_c_alpha_tilde: dec_key_alpha_tilde,
                ddh_proof_alpha,
                ddh_proof_alpha_tilde,
            },
            c_alpha,
            c_alpha_tilde,
        ))
    }

    pub fn verify_party_one_third_message_full_decrypt_and_conclude_division(
        c_alpha: &ElGamalCiphertext,
        c_alpha_tilde: &ElGamalCiphertext,
        party_one_third_message: &PartyOneCandidateGenerationThirdMsg,
        keys: &PartyTwoKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        // check that the randomization of the ciphertexts was done properly:
        let statement_alpha_ddh = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: c_alpha.c1.clone(),
            h1: party_one_third_message.c_alpha_random.c1.clone(),
            g2: c_alpha.c2.clone(),
            h2: party_one_third_message.c_alpha_random.c2.clone(),
        };
        let statement_alpha_tilde_ddh = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: c_alpha_tilde.c1.clone(),
            h1: party_one_third_message.c_alpha_tilde_random.c1.clone(),
            g2: c_alpha_tilde.c2.clone(),
            h2: party_one_third_message.c_alpha_tilde_random.c2.clone(),
        };
        if party_one_third_message
            .ddh_proof_alpha
            .verify(&statement_alpha_ddh)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        if party_one_third_message
            .ddh_proof_alpha_tilde
            .verify(&statement_alpha_tilde_ddh)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        // verify proofs of decryption:
        let statement_alpha = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.remote_elgamal_pubkey.h.clone(),
            g2: party_one_third_message.c_alpha_random.c1.clone(),
            h2: party_one_third_message.partial_dec_c_alpha.clone(),
        };
        let statement_alpha_tilde = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.remote_elgamal_pubkey.h.clone(),
            g2: party_one_third_message.c_alpha_tilde_random.c1.clone(),
            h2: party_one_third_message.partial_dec_c_alpha_tilde.clone(),
        };

        if party_one_third_message
            .proof_alpha
            .verify(&statement_alpha)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        if party_one_third_message
            .proof_alpha_tilde
            .verify(&statement_alpha_tilde)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        // full decryption
        let dec_key_alpha = BigInt::mod_pow(
            &party_one_third_message.c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &party_one_third_message.c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_full = BigInt::mod_mul(
            &dec_key_alpha,
            &party_one_third_message.partial_dec_c_alpha,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde_full = BigInt::mod_mul(
            &dec_key_alpha_tilde,
            &party_one_third_message.partial_dec_c_alpha_tilde,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        let dec_key_alpha_full_inv =
            BigInt::mod_inv(&dec_key_alpha_full, &keys.joint_elgamal_pubkey.pp.p).unwrap();
        let dec_key_alpha_tilde_full_inv =
            BigInt::mod_inv(&dec_key_alpha_tilde_full, &keys.joint_elgamal_pubkey.pp.p).unwrap();

        let test1 = BigInt::mod_mul(
            &party_one_third_message.c_alpha_random.c2,
            &dec_key_alpha_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let test2 = BigInt::mod_mul(
            &party_one_third_message.c_alpha_tilde_random.c2,
            &dec_key_alpha_tilde_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        if test1 == BigInt::one() || test2 == BigInt::one() {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

impl PartyTwoComputeProduct {
    pub fn verify_party_one_first_message_compute_c_n_p0_q0(
        party_one_first_message: &PartyOneComputeProductFirstMsg,
        p: &PartyTwoCandidateWitness,
        q: &PartyTwoCandidateWitness,
        keys: &PartyTwoKeySetup,
    ) -> Result<PartyTwoComputeProductFirstMsg, TwoPartyRSAError> {
        let ek = keys.remote_paillier_pubkey.clone();
        let statement_c_p = CiphertextStatement {
            ek: ek.clone(),
            c: party_one_first_message.c_p.clone(),
        };

        let statement_c_q = CiphertextStatement {
            ek: ek.clone(),
            c: party_one_first_message.c_q.clone(),
        };

        match party_one_first_message
            .c_p_proof
            .verify(&statement_c_p)
            .is_ok()
            && party_one_first_message
                .c_q_proof
                .verify(&statement_c_q)
                .is_ok()
        {
            true => {
                let p1q1 = BigInt::mod_mul(&p.p_1, &q.p_1, &ek.n);
                let r_p1q1 = BigInt::sample_below(&ek.n);
                let c_p1q1 = Paillier::encrypt_with_chosen_randomness(
                    &ek,
                    RawPlaintext::from(p1q1.clone()),
                    &Randomness(r_p1q1.clone()),
                );
                let c_p0_q1 = Paillier::mul(
                    &ek,
                    RawPlaintext::from(q.p_1.clone()),
                    RawCiphertext::from(party_one_first_message.c_p.clone()),
                );
                let c_q0_p1 = Paillier::mul(
                    &ek,
                    RawPlaintext::from(p.p_1.clone()),
                    RawCiphertext::from(party_one_first_message.c_q.clone()),
                );
                let c_p0_q1_q0_p1 = Paillier::add(&ek, c_p0_q1.clone(), c_q0_p1.clone());
                let c_n_p0_q0 = Paillier::add(&ek, c_p0_q1_q0_p1, c_p1q1).0.into_owned();

                let verlin_witness = VerlinWitness {
                    x: q.p_1.clone(),
                    x_prime: p.p_1.clone(),
                    x_double_prime: p1q1,
                    r_x: r_p1q1,
                };
                let verlin_statement = VerlinStatement {
                    ek,
                    c: party_one_first_message.c_p.clone(),
                    c_prime: party_one_first_message.c_q.clone(),
                    phi_x: c_n_p0_q0.clone(),
                };
                let proof = VerlinProof::prove(&verlin_witness, &verlin_statement);
                Ok(PartyTwoComputeProductFirstMsg {
                    c_n_p0_q0,
                    pi_verlin: proof,
                })
            }
            false => return Err(TwoPartyRSAError::InvalidEncProof),
        }
    }

    pub fn verify_party_one_second_message(
        party_one_first_message: &PartyOneComputeProductFirstMsg,
        party_two_first_message: &PartyTwoComputeProductFirstMsg,
        party_one_second_message: &PartyOneComputeProductSecondMsg,
        keys: &PartyTwoKeySetup,
    ) -> Result<BigInt, TwoPartyRSAError> {
        let mul_statement = MulStatement {
            ek: keys.remote_paillier_pubkey.clone(),
            e_a: party_one_first_message.c_p.clone(),
            e_b: party_one_first_message.c_q.clone(),
            e_c: party_one_second_message.c_pi.clone(),
        };

        let c_n_tilde = Paillier::encrypt_with_chosen_randomness(
            &keys.remote_paillier_pubkey,
            RawPlaintext::from(party_one_second_message.n_tilde.clone()),
            &Randomness(party_one_second_message.r_n_tilde.clone()),
        )
        .0
        .into_owned();
        let c_n_tilde_inv = BigInt::mod_inv(&c_n_tilde, &keys.remote_paillier_pubkey.nn).unwrap();
        let c_n_p0_q0_c_pi = Paillier::add(
            &keys.remote_paillier_pubkey,
            RawCiphertext::from(&party_two_first_message.c_n_p0_q0.clone()),
            RawCiphertext::from(party_one_second_message.c_pi.clone()),
        );
        let c_0 = Paillier::add(
            &keys.remote_paillier_pubkey,
            c_n_p0_q0_c_pi,
            RawCiphertext::from(c_n_tilde_inv.clone()),
        )
        .0
        .into_owned();
        let zero_statement = ZeroStatement {
            ek: keys.remote_paillier_pubkey.clone(),
            c: c_0,
        };

        match party_one_second_message
            .mul_proof
            .verify(&mul_statement)
            .is_ok()
            && party_one_second_message
                .zero_proof
                .verify(&zero_statement)
                .is_ok()
        {
            true => Ok(party_one_second_message.n_tilde.clone()),
            false => Err(TwoPartyRSAError::InvalidPartyOneProduct),
        }
    }

    pub fn verify_party_one_elgamal_mult_compute_p0q0_elgamal_ciphertext(
        party_one_ep_first_message: &PartyOneElgamalProductFirstMsg,
        p: &PartyTwoCandidateWitness,
        q: &PartyTwoCandidateWitness,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        keys: &PartyTwoKeySetup,
    ) -> Result<(PartyTwoElgamalProductFirstMsg, ElGamalCiphertext), TwoPartyRSAError> {
        // verify party one mul proof
        let mul_statement_eg = MulStatementElGamal {
            pk: keys.joint_elgamal_pubkey.clone(),
            e_a: ciphertext_pair_p_candidate.c0.clone(),
            e_b: ciphertext_pair_q_candidate.c0.clone(),
            e_c: party_one_ep_first_message.c_p0q0.clone(),
        };

        let mul_res = party_one_ep_first_message
            .mul_proof_eg
            .verify(&mul_statement_eg);
        match mul_res {
            Ok(_) => {
                // compute Enc(p1q1) and mult proof:
                let p1q1 = BigInt::mod_mul(&p.p_1, &q.p_1, &keys.joint_elgamal_pubkey.pp.q);
                let r_p1q1 = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
                let c_p1q1 = ExponentElGamal::encrypt_from_predefined_randomness(
                    &p1q1,
                    &keys.joint_elgamal_pubkey,
                    &r_p1q1,
                )
                .unwrap();
                let mul_witness_eg = MulWitnessElGamal {
                    a: p.p_1.clone(),
                    b: q.p_1.clone(),
                    c: p1q1.clone(),
                    r_a: p.r_1.clone(),
                    r_b: q.r_1.clone(),
                    r_c: r_p1q1.clone(),
                };

                let mul_statement_eg = MulStatementElGamal {
                    pk: keys.joint_elgamal_pubkey.clone(),
                    e_a: ciphertext_pair_p_candidate.c1.clone(),
                    e_b: ciphertext_pair_q_candidate.c1.clone(),
                    e_c: c_p1q1.clone(),
                };

                let mul_proof_eg =
                    MulProofElGamal::prove(&mul_witness_eg, &mul_statement_eg).unwrap();

                // compute Enc(N) and partial decrypt :
                let c_p0q1 = ExponentElGamal::mul(&ciphertext_pair_p_candidate.c0, &q.p_1);
                let c_q0p1 = ExponentElGamal::mul(&ciphertext_pair_q_candidate.c0, &p.p_1);
                let c_p0q1_q0p1 = ExponentElGamal::add(&c_p0q1, &c_q0p1).unwrap();
                let c_p0q1_q0p1_p1q1 = ExponentElGamal::add(&c_p0q1_q0p1, &c_p1q1).unwrap();

                let verlin_witness = VerlinWitnessElGamal {
                    x: q.p_1.clone(),
                    x_prime: p.p_1.clone(),
                    x_double_prime: p1q1,
                    r_x: r_p1q1,
                };
                let verlin_statement = VerlinStatementElGamal {
                    pk: keys.joint_elgamal_pubkey.clone(),
                    c: ciphertext_pair_p_candidate.c0.clone(),
                    c_prime: ciphertext_pair_q_candidate.c0.clone(),
                    phi_x: c_p0q1_q0p1_p1q1.clone(),
                };
                let verlin_proof =
                    VerlinProofElGamal::prove(&verlin_witness, &verlin_statement).unwrap();
                let c_n =
                    ExponentElGamal::add(&c_p0q1_q0p1_p1q1, &party_one_ep_first_message.c_p0q0)
                        .unwrap();

                let c_n_1_sk2 =
                    BigInt::mod_pow(&c_n.c1, &keys.private.sk.x, &keys.joint_elgamal_pubkey.pp.p);
                let ddh_statement = DDHStatement {
                    pp: keys.joint_elgamal_pubkey.pp.clone(),
                    g1: keys.joint_elgamal_pubkey.pp.g.clone(),
                    h1: keys.local_elgamal_pubkey.h.clone(),
                    g2: c_n.c1.clone(),
                    h2: c_n_1_sk2.clone(),
                };
                let ddh_witness = DDHWitness {
                    x: keys.private.sk.x.clone(),
                };
                let ddh_proof = DDHProof::prove(&ddh_witness, &ddh_statement);
                Ok((
                    PartyTwoElgamalProductFirstMsg {
                        c_p1q1,
                        mul_proof_eg,
                        c_p0q1_q0p1_p1q1,
                        verlin_proof,
                        c_n_1_sk2,
                        ddh_proof,
                    },
                    c_n,
                ))
            }

            Err(_) => Err(TwoPartyRSAError::InvalidElGamalMul),
        }
    }

    pub fn verify_decryption_and_biprime(
        party_one_ep_second_message: &PartyOneElgamalProductSecondMsg,
        party_two_ep_first_message: &PartyTwoElgamalProductFirstMsg,
        bi_prime_n_tilde: &BigInt,
        c_n: &ElGamalCiphertext,
        keys: &PartyTwoKeySetup,
    ) -> Result<(), TwoPartyRSAError> {
        let ddh_statement = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.remote_elgamal_pubkey.h.clone(),
            g2: c_n.c1.clone(),
            h2: party_one_ep_second_message.c_n_1_sk1.clone(),
        };

        match party_one_ep_second_message.ddh_proof.verify(&ddh_statement) {
            Ok(_) => {
                let key = BigInt::mod_mul(
                    &party_one_ep_second_message.c_n_1_sk1,
                    &party_two_ep_first_message.c_n_1_sk2,
                    &keys.joint_elgamal_pubkey.pp.p,
                );
                let key_inv = BigInt::mod_inv(&key, &keys.joint_elgamal_pubkey.pp.p).unwrap();
                let g_n = BigInt::mod_mul(&key_inv, &c_n.c2, &keys.joint_elgamal_pubkey.pp.p);
                let g_n_tilde = BigInt::mod_pow(
                    &keys.joint_elgamal_pubkey.pp.g,
                    &bi_prime_n_tilde,
                    &keys.joint_elgamal_pubkey.pp.p,
                );
                match g_n == g_n_tilde {
                    true => Ok(()),
                    false => Err(TwoPartyRSAError::BiPrimesNotEqual),
                }
            }
            Err(_) => Err(TwoPartyRSAError::InvalidDecryption),
        }
    }
}

// TODO: zeroize

impl PartyTwoBiPrimalityTest {
    // This function generates joint pubic randomness for gamma and h = ax + b (in TN).
    // We do this by hashing the candidate N together with the joint elgamal key and a seed
    // We next non interactively compute gamma_0 and u_0 (see [BF01]) together with pi_eq
    pub fn compute(
        n: &BigInt,
        p: &PartyTwoCandidateWitness,
        q: &PartyTwoCandidateWitness,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        keys: &PartyTwoKeySetup,
        seed: &BigInt,
    ) -> Self {
        let four = BigInt::from(4);
        let (gamma, h) =
            compute_randomness_for_biprimality_test(&n, &keys.joint_elgamal_pubkey.h, &seed);

        //compute e0:
        let c_p1_plus_q1 = ExponentElGamal::add(
            &ciphertext_pair_p_candidate.c1,
            &ciphertext_pair_q_candidate.c1,
        )
        .unwrap();
        //let c_minus_p1_plus_q1 = ExponentElGamal::mul(&c_p1_plus_q1, &(-BigInt::one()));
        let c_minus_p1_plus_q1 = crate::utlities::mul_neg_one(&c_p1_plus_q1);

        let four_inv = BigInt::mod_inv(&four, &keys.joint_elgamal_pubkey.pp.q).unwrap();
        let e_1 = ExponentElGamal::mul(&c_minus_p1_plus_q1, &four_inv);

        let r_e_1: BigInt = BigInt::mod_mul(
            &BigInt::mod_sub(
                &BigInt::zero(),
                &(&p.r_1 + &q.r_1),
                &keys.joint_elgamal_pubkey.pp.q,
            ),
            &four_inv,
            &keys.joint_elgamal_pubkey.pp.q,
        );
        let minus_p1_plus_q1_div_four: BigInt = (-(&p.p_1 + &q.p_1)).div_floor(&four);
        //let gamma_1 = BigInt::mod_pow(&gamma, &minus_p1_plus_q1_div_four, n);
        let p1_plus_q1_div_four: BigInt = (&p.p_1 + &q.p_1).div_floor(&four);
        let gamma_pow =  BigInt::mod_pow(&gamma, &p1_plus_q1_div_four, n);
        let gamma_1 = BigInt::mod_inv(&gamma_pow, n).unwrap();

        let p1_plus_q1: BigInt = &p.p_1 + &q.p_1;
        let u2 = TN::pow(&h, &p1_plus_q1, n);

        let gamma_eq_witness = EqWitness {
            x: minus_p1_plus_q1_div_four.clone(),
            r: r_e_1.clone(),
        };

        let gamma_eq_statement = EqStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: gamma.clone(),
            h_prime: gamma_1.clone(),
            n: n.clone(),
            ciphertext: e_1,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let eq_proof = EqProof::prove(&gamma_eq_statement, &gamma_eq_witness).unwrap();

        // repeat the proof but for u1:
        let r_q0_plus_p0: BigInt = &p.r_1 + &q.r_1;

        let h_eq_witness_tn = EqWitnessTN {
            x: p1_plus_q1,
            r: r_q0_plus_p0,
        };

        let h_eq_statement_tn = EqStatementTN {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: h.clone(),
            h_prime: u2.clone(),
            n: n.clone(),
            ciphertext: c_p1_plus_q1,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let eq_proof_tn = EqProofTN::prove(&h_eq_statement_tn, &h_eq_witness_tn).unwrap();

        return PartyTwoBiPrimalityTest {
            gamma_1,
            u2,
            eq_proof,
            eq_proof_tn,
        };
    }

    pub fn verify(
        &self,
        n: &BigInt,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        party_one_biprime_test: &PartyOneBiPrimalityTest,
        seed: &BigInt,
        keys: &PartyTwoKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        let (gamma, h) =
            compute_randomness_for_biprimality_test(&n, &keys.joint_elgamal_pubkey.h, &seed);
        let four = BigInt::from(4);

        let c_p0_plus_q0 = ExponentElGamal::add(
            &ciphertext_pair_p_candidate.c0,
            &ciphertext_pair_q_candidate.c0,
        )
        .unwrap();
        //let c_minus_p0_plus_q0 = ExponentElGamal::mul(&c_p0_plus_q0, &(-BigInt::one()));
        let c_minus_p0_plus_q0 = crate::utlities::mul_neg_one(&c_p0_plus_q0);
        let c_n_plus_one = ExponentElGamal::encrypt_from_predefined_randomness(
            &(n + BigInt::one()).modulus(&keys.joint_elgamal_pubkey.pp.q),
            &keys.joint_elgamal_pubkey,
            &BigInt::from(2),
        )
        .unwrap();
        let c_n_minus_p0_plus_q0_plus_one =
            ExponentElGamal::add(&c_n_plus_one, &c_minus_p0_plus_q0).unwrap();
        let four_inv = BigInt::mod_inv(&four, &keys.joint_elgamal_pubkey.pp.q).unwrap();
        let e_0 = ExponentElGamal::mul(&c_n_minus_p0_plus_q0_plus_one, &four_inv);

        let gamma_eq_statement = EqStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: gamma.clone(),
            h_prime: party_one_biprime_test.gamma_0.clone(),
            n: n.clone(),
            ciphertext: e_0,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let c_n_plus_p0_plus_q0_plus_1 =
            ExponentElGamal::add(&c_n_plus_one, &c_p0_plus_q0).unwrap();
        let h_eq_statement_tn = EqStatementTN {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: h.clone(),
            h_prime: party_one_biprime_test.u1.clone(),
            n: n.clone(),
            ciphertext: c_n_plus_p0_plus_q0_plus_1,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        match party_one_biprime_test
            .eq_proof
            .verify(&gamma_eq_statement)
            .is_ok()
            && party_one_biprime_test
                .eq_proof_tn
                .verify(&h_eq_statement_tn)
                .is_ok()
        {
            true => {
                let gamma_test = BigInt::mod_mul(&self.gamma_1, &party_one_biprime_test.gamma_0, n);

                let h_test = TN::mul(&self.u2, &party_one_biprime_test.u1, n);
                if (gamma_test == BigInt::one() || gamma_test == (n - BigInt::one()))
                    && h_test.a == BigInt::zero()
                {
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            }
            false => return Err(TwoPartyRSAError::BiPrimalityTestError),
        }
    }
}

impl PartyTwoCandidateGenerationSemiHonest {
    pub fn generate_shares_of_candidate_semi_honest_inject(
        keys: &PartyTwoKeySetup,
        prime_share: &BigInt,
    ) -> (
        PartyTwoCandidateWitness,
        PartyTwoCandidateGenerationFirstMsgSemiHonest,
    ) {
        let p_i = prime_share;
        let r_i = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_i = ExponentElGamal::encrypt_from_predefined_randomness(
            p_i,
            &keys.joint_elgamal_pubkey,
            &r_i,
        )
        .unwrap();

        (
            PartyTwoCandidateWitness {
                p_1: p_i.clone(),
                r_1: r_i,
            },
            PartyTwoCandidateGenerationFirstMsgSemiHonest { c_i },
        )
    }

    pub fn generate_shares_of_candidate_semi_honest(
        keys: &PartyTwoKeySetup,
    ) -> (
        PartyTwoCandidateWitness,
        PartyTwoCandidateGenerationFirstMsgSemiHonest,
    ) {
        let share_bit_size: usize = CANDIDATE_BIT_LENGTH / 2 - 2;
        let p_i = BigInt::sample(share_bit_size);
        let r_i = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_i = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_i,
            &keys.joint_elgamal_pubkey,
            &r_i,
        )
        .unwrap();

        (
            PartyTwoCandidateWitness { p_1: p_i, r_1: r_i },
            PartyTwoCandidateGenerationFirstMsgSemiHonest { c_i },
        )
    }

    pub fn verify_party_one_first_message_and_normalize_ciphertexts_semi_honest(
        keys: &PartyTwoKeySetup,
        party_one_first_message: &PartyOneCandidateGenerationFirstMsgSemiHonest,
        party_two_first_message: &PartyTwoCandidateGenerationFirstMsgSemiHonest,
    ) -> Result<CiphertextPair, TwoPartyRSAError> {
        let c_party_one_mul_4 =
            ExponentElGamal::mul(&party_one_first_message.c_i, &BigInt::from(4));
        let c_party_two_mul_4 =
            ExponentElGamal::mul(&party_two_first_message.c_i, &BigInt::from(4));
        Ok(CiphertextPair {
            c0: ExponentElGamal::add(
                &c_party_one_mul_4,
                &ExponentElGamal::encrypt_from_predefined_randomness(
                    &BigInt::from(3),
                    &keys.joint_elgamal_pubkey,
                    &BigInt::zero(),
                )
                .unwrap(),
            )
            .unwrap(),
            c1: c_party_two_mul_4,
        })
    }

    pub fn trial_division_prepare_c_alpha_semi_honest(
        alpha: &BigInt,
        keys: &PartyTwoKeySetup,
        _c: &CiphertextPair,
        w: &PartyTwoCandidateWitness,
    ) -> Result<PartyTwoCandidateGenerationSecondMsgSemiHonest, TwoPartyRSAError> {
        // update witness:
        let p_1 = BigInt::mod_mul(&w.p_1, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q);
        let p_1_mod_alpha = p_1.mod_floor(alpha);
        let r_1_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let c_1_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_1_mod_alpha,
            &keys.joint_elgamal_pubkey,
            &r_1_alpha,
        )
        .unwrap();

        Ok(PartyTwoCandidateGenerationSecondMsgSemiHonest { c_1_alpha })
    }

    pub fn verify_party_one_second_message_and_partial_decrypt_semi_honest(
        party_one_second_message: &PartyOneCandidateGenerationSecondMsgSemiHonest,
        party_two_second_message: &PartyTwoCandidateGenerationSecondMsgSemiHonest,
        alpha: &BigInt,
        keys: &PartyTwoKeySetup,
        _c: &CiphertextPair,
    ) -> Result<
        (
            PartyTwoCandidateGenerationThirdMsgSemiHonest,
            ElGamalCiphertext,
            ElGamalCiphertext,
        ),
        TwoPartyRSAError,
    > {
        let c_alpha = ExponentElGamal::add(
            &party_one_second_message.c_0_alpha,
            &party_two_second_message.c_1_alpha,
        )
        .unwrap();
        // Enc(-alpha) is known to both parties therefore we use a predefined randomness known to both (r = 2)
        let enc_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            alpha,
            &keys.joint_elgamal_pubkey,
            &BigInt::from(2),
        )
        .unwrap();
        //let enc_minus_alpha = ExponentElGamal::mul(&enc_alpha, &(-BigInt::one()));
        let enc_minus_alpha = crate::utlities::mul_neg_one(&enc_alpha);
        let c_alpha_tilde = ExponentElGamal::add(&c_alpha, &enc_minus_alpha).unwrap();

        // we raise each ciphertext with a secret random number
        let r_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let r_alpha_tilde = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_alpha_random = ExponentElGamal::mul(&c_alpha, &r_alpha);
        let c_alpha_tilde_random = ExponentElGamal::mul(&c_alpha_tilde, &r_alpha_tilde);

        let dec_key_alpha = BigInt::mod_pow(
            &c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        Ok((
            PartyTwoCandidateGenerationThirdMsgSemiHonest {
                c_alpha_random,
                c_alpha_tilde_random,
                partial_dec_c_alpha: dec_key_alpha,
                partial_dec_c_alpha_tilde: dec_key_alpha_tilde,
            },
            c_alpha,
            c_alpha_tilde,
        ))
    }

    pub fn verify_party_one_third_message_full_decrypt_and_conclude_division_semi_honest(
        _c_alpha: &ElGamalCiphertext,
        _c_alpha_tilde: &ElGamalCiphertext,
        party_one_third_message: &PartyOneCandidateGenerationThirdMsgSemiHonest,
        keys: &PartyTwoKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        // check that the randomization of the ciphertexts was done properly:

        // full decryption
        let dec_key_alpha = BigInt::mod_pow(
            &party_one_third_message.c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &party_one_third_message.c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_full = BigInt::mod_mul(
            &dec_key_alpha,
            &party_one_third_message.partial_dec_c_alpha,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde_full = BigInt::mod_mul(
            &dec_key_alpha_tilde,
            &party_one_third_message.partial_dec_c_alpha_tilde,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        let dec_key_alpha_full_inv =
            BigInt::mod_inv(&dec_key_alpha_full, &keys.joint_elgamal_pubkey.pp.p).unwrap();
        let dec_key_alpha_tilde_full_inv =
            BigInt::mod_inv(&dec_key_alpha_tilde_full, &keys.joint_elgamal_pubkey.pp.p).unwrap();

        let test1 = BigInt::mod_mul(
            &party_one_third_message.c_alpha_random.c2,
            &dec_key_alpha_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let test2 = BigInt::mod_mul(
            &party_one_third_message.c_alpha_tilde_random.c2,
            &dec_key_alpha_tilde_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        if test1 == BigInt::one() || test2 == BigInt::one() {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
