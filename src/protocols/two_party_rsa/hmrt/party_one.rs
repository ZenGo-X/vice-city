use crate::protocols::two_party_rsa::hmrt::compute_randomness_for_biprimality_test;
use crate::protocols::two_party_rsa::hmrt::gen_ddh_containers;
use crate::protocols::two_party_rsa::hmrt::party_two::KeySetupFirstMsg as KeySetupFirstMsgPartyTwo;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoBiPrimalityTest;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationFirstMsg;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationSecondMsg;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationThirdMsg;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoComputeProductFirstMsg;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoElgamalProductFirstMsg;
use crate::protocols::two_party_rsa::hmrt::CiphertextPair;
use crate::protocols::two_party_rsa::CANDIDATE_BIT_LENGTH;
use crate::protocols::two_party_rsa::PAILLIER_MODULUS;
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
use crate::utlities::verlin_proof::VerlinStatementElGamal;
use crate::utlities::TN;
use crate::TwoPartyRSAError;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::rfc7919_groups::SupportedGroups;
use elgamal::ElGamalCiphertext;
use elgamal::ElGamalKeyPair;
use elgamal::ElGamalPP;
use elgamal::ElGamalPrivateKey;
use elgamal::ElGamalPublicKey;
use elgamal::ExponentElGamal;
use paillier::core::Randomness;
use paillier::traits::Add;
use paillier::traits::KeyGeneration;
use paillier::DecryptionKey;
use paillier::EncryptWithChosenRandomness;
use paillier::EncryptionKey;
use paillier::Open;
use paillier::Paillier;
use paillier::{RawCiphertext, RawPlaintext};
use zk_paillier::zkproofs::CiphertextWitness;
use zk_paillier::zkproofs::NICorrectKeyProof;
use zk_paillier::zkproofs::VerlinStatement;
use zk_paillier::zkproofs::SALT_STRING;
use zk_paillier::zkproofs::{CiphertextProof, CiphertextStatement};
use zk_paillier::zkproofs::{MulProof, MulStatement, MulWitness};
use zk_paillier::zkproofs::{ZeroProof, ZeroStatement, ZeroWitness};
use crate::protocols::two_party_rsa::SEC_PARAM;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationFirstMsgSemiHonest;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationSecondMsgSemiHonest;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGenerationThirdMsgSemiHonest;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneKeySetup {
    pub local_paillier_pubkey: EncryptionKey,
    pub local_elgamal_pubkey: ElGamalPublicKey,
    pub remote_paillier_pubkey: EncryptionKey,
    pub remote_elgamal_pubkey: ElGamalPublicKey,
    pub joint_elgamal_pubkey: ElGamalPublicKey,
    private: PartyOnePrivate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneKeySetupFirstMsg {
    pub ek: EncryptionKey,
    pub pk: ElGamalPublicKey,
    pub correct_key_proof: NICorrectKeyProof,
    pub dlog_proof: DLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOnePrivate {
    dk: DecryptionKey,
    sk: ElGamalPrivateKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationSemiHonest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationFirstMsgSemiHonest {
    pub c_i: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationSecondMsgSemiHonest {
    pub c_0_alpha: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationThirdMsgSemiHonest {
    pub c_alpha_random: ElGamalCiphertext,
    pub c_alpha_tilde_random: ElGamalCiphertext,
    pub partial_dec_c_alpha: BigInt,
    pub partial_dec_c_alpha_tilde: BigInt,
}



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGeneration {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationFirstMsg {
    pub c_i: ElGamalCiphertext,
    pub pi_enc: HomoELGamalProof,
    pub pi_bound: RangeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationSecondMsg {
    pub pi_mod: ModProof,
    pub c_0_alpha: ElGamalCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneCandidateGenerationThirdMsg {
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
pub struct PartyOneCandidateWitness {
    pub p_0: BigInt,
    pub r_0: BigInt,
    pub r_0_paillier: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneComputeProduct {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneComputeProductFirstMsg {
    pub c_p: BigInt,
    pub c_q: BigInt,
    pub c_p_proof: CiphertextProof,
    pub c_q_proof: CiphertextProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneComputeProductSecondMsg {
    pub zero_proof: ZeroProof,
    pub mul_proof: MulProof,
    pub n_tilde: BigInt,
    pub r_n_tilde: BigInt,
    pub c_pi: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneElgamalProductFirstMsg {
    pub c_p0q0: ElGamalCiphertext,
    pub mul_proof_eg: MulProofElGamal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneElgamalProductSecondMsg {
    pub c_n_1_sk1: BigInt,
    pub ddh_proof: DDHProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyOneBiPrimalityTest {
    pub gamma_0: BigInt,
    pub u1: TN,
    pub eq_proof: EqProof,
    pub eq_proof_tn: EqProofTN,
}

impl PartyOneKeySetup {
    pub fn gen_local_keys_and_first_message_to_party_two(
    ) -> (PartyOneKeySetupFirstMsg, PartyOnePrivate) {
        let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
        let keypair = ElGamalKeyPair::generate(&pp);
        let witness = DLogWitness {
            //TODO: zeroize
            x: keypair.sk.x.clone(),
        };
        let dlog_proof = DLogProof::prove(&witness, &pp);

        let (ek_new, dk_new) = Paillier::keypair_with_modulus_size(PAILLIER_MODULUS).keys();
        let correct_key_proof = NICorrectKeyProof::proof(&dk_new, None);

        let party_one_private = PartyOnePrivate {
            dk: dk_new,
            sk: keypair.sk,
        };
        (
            PartyOneKeySetupFirstMsg {
                ek: ek_new,
                pk: keypair.pk,
                correct_key_proof,
                dlog_proof,
            },
            party_one_private,
        )
    }

    pub fn verify_party_two_first_message_and_output_party_one_keys(
        party_one_first_message: &PartyOneKeySetupFirstMsg,
        party_two_first_message: &KeySetupFirstMsgPartyTwo,
        party_one_private: PartyOnePrivate,
    ) -> Result<Self, TwoPartyRSAError> {
        let dlog_statement = DLogStatement {
            h: party_two_first_message.pk.h.clone(),
        };

        match party_two_first_message
            .dlog_proof
            .verify(&dlog_statement, &party_one_first_message.pk.pp)
        {
            Ok(()) => {
                match party_two_first_message
                    .correct_key_proof
                    .verify(&party_two_first_message.ek, SALT_STRING)
                {
                    Ok(()) => Ok(PartyOneKeySetup {
                        local_paillier_pubkey: party_one_first_message.ek.clone(),
                        local_elgamal_pubkey: party_one_first_message.pk.clone(),
                        remote_paillier_pubkey: party_two_first_message.ek.clone(),
                        remote_elgamal_pubkey: party_two_first_message.pk.clone(),
                        joint_elgamal_pubkey: party_one_first_message
                            .pk
                            .add(&party_two_first_message.pk)
                            .unwrap(),
                        private: party_one_private,
                    }),
                    Err(_) => Err(TwoPartyRSAError::InvalidPaillierKey),
                }
            }
            Err(_) => Err(TwoPartyRSAError::InvalidElGamalKey),
        }
    }
}

impl PartyOneCandidateGeneration {

    pub fn generate_shares_of_candidate(
        keys: &PartyOneKeySetup,
    ) -> (
        PartyOneCandidateWitness,
        PartyOneCandidateGenerationFirstMsg,
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
            // TODO: in current range proof this will give some slack such that it is possible that a prover chose 2^(N/2-2)<x< 1/3 * 2^(N/2).
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: c_i.clone(),
            sec_param: SEC_PARAM, //TODO : parameterize
            kapa: 100,      //TODO : parameterize
        };

        let enc_proof = HomoELGamalProof::prove(&enc_witness, &enc_statement);
        let bound_proof = RangeProof::prove(&bound_witness, &bound_statement).unwrap(); // TODO: handle error properly

        (
            PartyOneCandidateWitness {
                p_0: p_i,
                r_0: r_i,
                r_0_paillier: BigInt::zero(),
            },
            PartyOneCandidateGenerationFirstMsg {
                c_i,
                pi_enc: enc_proof,
                pi_bound: bound_proof,
            },
        )
    }

    pub fn generate_shares_of_candidate_inject(
        keys: &PartyOneKeySetup,
        prime_share: BigInt,
    ) -> (
        PartyOneCandidateWitness,
        PartyOneCandidateGenerationFirstMsg,
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
            // TODO: in current range proof this will give some slack such that it is possible that a prover chose 2^(N/2-2)<x< 1/3 * 2^(N/2).
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: c_i.clone(),
            sec_param: SEC_PARAM,
            kapa: 100,      //TODO : parameterize
        };

        let enc_proof = HomoELGamalProof::prove(&enc_witness, &enc_statement);
        let bound_proof = RangeProof::prove(&bound_witness, &bound_statement).unwrap(); // TODO: handle error properly

        (
            PartyOneCandidateWitness {
                p_0: p_i,
                r_0: r_i,
                r_0_paillier: BigInt::zero(),
            },
            PartyOneCandidateGenerationFirstMsg {
                c_i,
                pi_enc: enc_proof,
                pi_bound: bound_proof,
            },
        )
    }






    pub fn verify_party_two_first_message_and_normalize_ciphertexts(
        keys: &PartyOneKeySetup,
        party_one_first_message: &PartyOneCandidateGenerationFirstMsg,
        party_two_first_message: &PartyTwoCandidateGenerationFirstMsg,
    ) -> Result<CiphertextPair, TwoPartyRSAError> {
        let enc_statement = HomoElGamalStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            ciphertext: party_two_first_message.c_i.clone(),
        };

        let bound_statement = BoundStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            range: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            ciphertext: party_two_first_message.c_i.clone(),
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        match party_two_first_message
            .pi_enc
            .verify(&enc_statement)
            .is_ok()
            && party_two_first_message
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
        keys: &PartyOneKeySetup,
        c: &CiphertextPair,
        w: &PartyOneCandidateWitness,
    ) -> Result<PartyOneCandidateGenerationSecondMsg, TwoPartyRSAError> {
        // update witness:
        let p_0 = BigInt::mod_add(
            &BigInt::mod_mul(&w.p_0, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q),
            &BigInt::from(3),
            &keys.joint_elgamal_pubkey.pp.q,
        );
        let r_0 = BigInt::mod_mul(&w.r_0, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q);

        let p_0_mod_alpha = p_0.mod_floor(alpha);
        let r_0_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let c_0_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_0_mod_alpha,
            &keys.joint_elgamal_pubkey,
            &r_0_alpha,
        )
        .unwrap();

        let mod_statement = ModStatement {
            c: c.c0.clone(),
            c_prime: c_0_alpha.clone(),
            modulus_p: alpha.clone(),
            upper_bound_m: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32), // n/2 instead of n/2-2 as is written in the paper : we suspect paper has a typo and do not consider the fact that ciphertexts and plaintext are scaled by mul4
            pk: keys.joint_elgamal_pubkey.clone(),
        };

        let mod_witness = ModWitness {
            r_a: r_0,
            a: p_0,
            r_b: r_0_alpha,
            b: p_0_mod_alpha,
        };

        let proof = ModProof::prove(&mod_witness, &mod_statement);

        match proof {
            Ok(_) => Ok(PartyOneCandidateGenerationSecondMsg {
                pi_mod: proof.unwrap(),
                c_0_alpha,
            }),
            Err(_) => Err(TwoPartyRSAError::InvalidModProof),
        }
    }


    pub fn verify_party_two_second_message_and_partial_decrypt(
        party_one_second_message: &PartyOneCandidateGenerationSecondMsg,
        party_two_second_message: &PartyTwoCandidateGenerationSecondMsg,
        alpha: &BigInt,
        keys: &PartyOneKeySetup,
        c: &CiphertextPair,
    ) -> Result<
        (
            PartyOneCandidateGenerationThirdMsg,
            ElGamalCiphertext,
            ElGamalCiphertext,
        ),
        TwoPartyRSAError,
    > {
        let mod_statement = ModStatement {
            c: c.c1.clone(),
            c_prime: party_two_second_message.c_1_alpha.clone(),
            modulus_p: alpha.clone(),
            upper_bound_m: BigInt::from(2).pow((CANDIDATE_BIT_LENGTH / 2) as u32),
            pk: keys.joint_elgamal_pubkey.clone(),
        };
        let verify = party_two_second_message.pi_mod.verify(&mod_statement);
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
        let enc_minus_alpha = ExponentElGamal::mul(&enc_alpha, &(-BigInt::one()));
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
        let witness_alpha_tilde = DDHWitness {
            x: keys.private.sk.x.clone(),
        };

        let proof_alpha = DDHProof::prove(&witness_alpha, &statement_alpha);
        let proof_alpha_tilde = DDHProof::prove(&witness_alpha_tilde, &statement_alpha_tilde);

        Ok((
            PartyOneCandidateGenerationThirdMsg {
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

    pub fn verify_party_two_third_message_full_decrypt_and_conclude_division(
        c_alpha: &ElGamalCiphertext,
        c_alpha_tilde: &ElGamalCiphertext,
        party_two_third_message: &PartyTwoCandidateGenerationThirdMsg,
        keys: &PartyOneKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        // check that the randomization of the ciphertexts was done properly:
        let statement_alpha_ddh = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: c_alpha.c1.clone(),
            h1: party_two_third_message.c_alpha_random.c1.clone(),
            g2: c_alpha.c2.clone(),
            h2: party_two_third_message.c_alpha_random.c2.clone(),
        };
        let statement_alpha_tilde_ddh = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: c_alpha_tilde.c1.clone(),
            h1: party_two_third_message.c_alpha_tilde_random.c1.clone(),
            g2: c_alpha_tilde.c2.clone(),
            h2: party_two_third_message.c_alpha_tilde_random.c2.clone(),
        };
        if party_two_third_message
            .ddh_proof_alpha
            .verify(&statement_alpha_ddh)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        if party_two_third_message
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
            g2: party_two_third_message.c_alpha_random.c1.clone(),
            h2: party_two_third_message.partial_dec_c_alpha.clone(),
        };
        let statement_alpha_tilde = DDHStatement {
            pp: keys.joint_elgamal_pubkey.pp.clone(),
            g1: keys.joint_elgamal_pubkey.pp.g.clone(),
            h1: keys.remote_elgamal_pubkey.h.clone(),
            g2: party_two_third_message.c_alpha_tilde_random.c1.clone(),
            h2: party_two_third_message.partial_dec_c_alpha_tilde.clone(),
        };

        if party_two_third_message
            .proof_alpha
            .verify(&statement_alpha)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        if party_two_third_message
            .proof_alpha_tilde
            .verify(&statement_alpha_tilde)
            .is_err()
        {
            return Err(TwoPartyRSAError::CandidateGenerationDecError);
        }

        // full decryption
        let dec_key_alpha = BigInt::mod_pow(
            &party_two_third_message.c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &party_two_third_message.c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_full = BigInt::mod_mul(
            &dec_key_alpha,
            &party_two_third_message.partial_dec_c_alpha,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde_full = BigInt::mod_mul(
            &dec_key_alpha_tilde,
            &party_two_third_message.partial_dec_c_alpha_tilde,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        let dec_key_alpha_full_inv =
            BigInt::mod_inv(&dec_key_alpha_full, &keys.joint_elgamal_pubkey.pp.p);
        let dec_key_alpha_tilde_full_inv =
            BigInt::mod_inv(&dec_key_alpha_tilde_full, &keys.joint_elgamal_pubkey.pp.p);

        let test1 = BigInt::mod_mul(
            &party_two_third_message.c_alpha_random.c2,
            &dec_key_alpha_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let test2 = BigInt::mod_mul(
            &party_two_third_message.c_alpha_tilde_random.c2,
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

impl PartyOneComputeProduct {
    pub fn send_candidate_ciphertexts(
        p: &mut PartyOneCandidateWitness,
        q: &mut PartyOneCandidateWitness,
        keys: &PartyOneKeySetup,
    ) -> PartyOneComputeProductFirstMsg {
        let r_p = BigInt::sample_below(&keys.local_paillier_pubkey.n);
        let r_q = BigInt::sample_below(&keys.local_paillier_pubkey.n);
        // we abuse existing PartyOneCandidateWitness to handle the paillier encryption randomness
        p.r_0_paillier = r_p.clone();
        q.r_0_paillier = r_q.clone();
        let c_p = Paillier::encrypt_with_chosen_randomness(
            &keys.local_paillier_pubkey,
            RawPlaintext::from(p.p_0.clone()),
            &Randomness(r_p.clone()),
        )
        .0
        .into_owned();
        let c_q = Paillier::encrypt_with_chosen_randomness(
            &keys.local_paillier_pubkey,
            RawPlaintext::from(q.p_0.clone()),
            &Randomness(r_q.clone()),
        )
        .0
        .into_owned();

        let witness_c_p = CiphertextWitness {
            x: p.p_0.clone(),
            r: r_p,
        };

        let witness_c_q = CiphertextWitness {
            x: q.p_0.clone(),
            r: r_q,
        };

        let statement_c_p = CiphertextStatement {
            ek: keys.local_paillier_pubkey.clone(),
            c: c_p.clone(),
        };

        let statement_c_q = CiphertextStatement {
            ek: keys.local_paillier_pubkey.clone(),
            c: c_q.clone(),
        };

        let c_p_proof = CiphertextProof::prove(&witness_c_p, &statement_c_p).unwrap();
        let c_q_proof = CiphertextProof::prove(&witness_c_q, &statement_c_q).unwrap();

        PartyOneComputeProductFirstMsg {
            c_p,
            c_q,
            c_p_proof,
            c_q_proof,
        }
    }

    pub fn verify_party_two_first_message_decrypt_compute_n(
        party_one_first_message: &PartyOneComputeProductFirstMsg,
        party_two_first_message: &PartyTwoComputeProductFirstMsg,
        p: &PartyOneCandidateWitness,
        q: &PartyOneCandidateWitness,
        keys: &PartyOneKeySetup,
    ) -> Result<PartyOneComputeProductSecondMsg, TwoPartyRSAError> {
        let verlin_statement = VerlinStatement {
            ek: keys.local_paillier_pubkey.clone(),
            c: party_one_first_message.c_p.clone(),
            c_prime: party_one_first_message.c_q.clone(),
            phi_x: party_two_first_message.c_n_p0_q0.clone(),
        };
        if party_two_first_message
            .pi_verlin
            .verify(&verlin_statement)
            .is_err()
        {
            return Err(TwoPartyRSAError::InvalidVerlinProof);
        }

        let (n_minus_p0_q0, r_n_minus_p0_q0) = Paillier::open(
            &keys.private.dk,
            RawCiphertext::from(party_two_first_message.c_n_p0_q0.clone()),
        );
        let p0q0 = &p.p_0 * &q.p_0;
        let n_tilde: BigInt = &n_minus_p0_q0.0.into_owned() + &p0q0;
        if n_tilde > keys.local_paillier_pubkey.n {
            return Err(TwoPartyRSAError::GeneralError);
        }
        let r_pi = BigInt::sample_below(&keys.local_paillier_pubkey.n);
        let c_pi = Paillier::encrypt_with_chosen_randomness(
            &keys.local_paillier_pubkey,
            RawPlaintext::from(p0q0.clone()),
            &Randomness(r_pi.clone()),
        )
        .0
        .into_owned();
        let mult_witness = MulWitness {
            a: p.p_0.clone(),
            b: q.p_0.clone(),
            c: p0q0.clone(),
            r_a: p.r_0_paillier.clone(),
            r_b: q.r_0_paillier.clone(),
            r_c: r_pi.clone(),
        };

        let mult_statement = MulStatement {
            ek: keys.local_paillier_pubkey.clone(),
            e_a: party_one_first_message.c_p.clone(),
            e_b: party_one_first_message.c_q.clone(),
            e_c: c_pi.clone(),
        };
        let mul_proof = MulProof::prove(&mult_witness, &mult_statement).unwrap();

        let r_n_tilde = BigInt::sample_below(&keys.local_paillier_pubkey.n);
        let r_n_tilde_inv = r_n_tilde.invert(&keys.local_paillier_pubkey.nn).unwrap();
        let c_n_tilde = Paillier::encrypt_with_chosen_randomness(
            &keys.local_paillier_pubkey,
            RawPlaintext::from(n_tilde.clone()),
            &Randomness(r_n_tilde.clone()),
        )
        .0
        .into_owned();
        let c_n_tilde_inv = c_n_tilde.invert(&keys.local_paillier_pubkey.nn).unwrap();
        let c_n_p0_q0_c_pi = Paillier::add(
            &keys.local_paillier_pubkey,
            RawCiphertext::from(&party_two_first_message.c_n_p0_q0.clone()),
            RawCiphertext::from(c_pi.clone()),
        );
        let c_0 = Paillier::add(
            &keys.local_paillier_pubkey,
            c_n_p0_q0_c_pi,
            RawCiphertext::from(c_n_tilde_inv.clone()),
        )
        .0
        .into_owned();

        let zero_witness = ZeroWitness {
            r: BigInt::mod_mul(
                &BigInt::mod_mul(&r_pi, &r_n_minus_p0_q0.0, &keys.local_paillier_pubkey.nn),
                &r_n_tilde_inv,
                &keys.local_paillier_pubkey.nn,
            ),
        };
        let zero_statement = ZeroStatement {
            ek: keys.local_paillier_pubkey.clone(),
            c: c_0,
        };

        let zero_proof = ZeroProof::prove(&zero_witness, &zero_statement).unwrap();
        return Ok(PartyOneComputeProductSecondMsg {
            zero_proof,
            mul_proof,
            r_n_tilde,
            n_tilde,
            c_pi,
        });
    }

    pub fn compute_p0q0_elgamal_ciphertext(
        p: &PartyOneCandidateWitness,
        q: &PartyOneCandidateWitness,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        keys: &PartyOneKeySetup,
    ) -> PartyOneElgamalProductFirstMsg {
        // start of 3(b)
        // in 3(b) P1 should send Enc_eg(p0q0) to P2 together with pi_mult
        let p0q0 = BigInt::mod_mul(&p.p_0, &q.p_0, &keys.joint_elgamal_pubkey.pp.q);
        let r_p0q0 = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let c_p0q0 = ExponentElGamal::encrypt_from_predefined_randomness(
            &p0q0,
            &keys.joint_elgamal_pubkey,
            &r_p0q0,
        )
        .unwrap();
        let mul_witness_eg = MulWitnessElGamal {
            a: p.p_0.clone(),
            b: q.p_0.clone(),
            c: p0q0,
            r_a: p.r_0.clone(),
            r_b: q.r_0.clone(),
            r_c: r_p0q0,
        };

        let mul_statement_eg = MulStatementElGamal {
            pk: keys.joint_elgamal_pubkey.clone(),
            e_a: ciphertext_pair_p_candidate.c0.clone(),
            e_b: ciphertext_pair_q_candidate.c0.clone(),
            e_c: c_p0q0.clone(),
        };

        let mul_proof_eg = MulProofElGamal::prove(&mul_witness_eg, &mul_statement_eg).unwrap();

        PartyOneElgamalProductFirstMsg {
            c_p0q0,
            mul_proof_eg,
        }
    }

    pub fn compute_elgamal_c_n_and_verify_biprime_correctness(
        party_one_ep_first_message: &PartyOneElgamalProductFirstMsg,
        party_two_ep_first_message: &PartyTwoElgamalProductFirstMsg,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        bi_prime_n_tilde: &BigInt,
        keys: &PartyOneKeySetup,
    ) -> Result<PartyOneElgamalProductSecondMsg, TwoPartyRSAError> {
        // verify party two mul proof and verlin proof
        let mul_statement_eg = MulStatementElGamal {
            pk: keys.joint_elgamal_pubkey.clone(),
            e_a: ciphertext_pair_p_candidate.c1.clone(),
            e_b: ciphertext_pair_q_candidate.c1.clone(),
            e_c: party_two_ep_first_message.c_p1q1.clone(),
        };
        let verlin_statement_eg = VerlinStatementElGamal {
            pk: keys.joint_elgamal_pubkey.clone(),
            c: ciphertext_pair_p_candidate.c0.clone(),
            c_prime: ciphertext_pair_q_candidate.c0.clone(),
            phi_x: party_two_ep_first_message.c_p0q1_q0p1_p1q1.clone(),
        };

        let verlin_res = party_two_ep_first_message
            .verlin_proof
            .verify(&verlin_statement_eg);
        let mul_res = party_two_ep_first_message
            .mul_proof_eg
            .verify(&mul_statement_eg);
        match mul_res.is_ok() && verlin_res.is_ok() {
            true => {
                let c_n = ExponentElGamal::add(
                    &party_two_ep_first_message.c_p0q1_q0p1_p1q1,
                    &party_one_ep_first_message.c_p0q0,
                )
                .unwrap();

                //verify ddh proof from party 2 decryption
                let ddh_statement_to_verify = DDHStatement {
                    pp: keys.joint_elgamal_pubkey.pp.clone(),
                    g1: keys.joint_elgamal_pubkey.pp.g.clone(),
                    h1: keys.remote_elgamal_pubkey.h.clone(),
                    g2: c_n.c1.clone(),
                    h2: party_two_ep_first_message.c_n_1_sk2.clone(),
                };
                if party_two_ep_first_message
                    .ddh_proof
                    .verify(&ddh_statement_to_verify)
                    .is_err()
                {
                    return Err(TwoPartyRSAError::InvalidDecryption);
                }

                let c_n_1_sk1 =
                    BigInt::mod_pow(&c_n.c1, &keys.private.sk.x, &keys.joint_elgamal_pubkey.pp.p);
                let ddh_statement = DDHStatement {
                    pp: keys.joint_elgamal_pubkey.pp.clone(),
                    g1: keys.joint_elgamal_pubkey.pp.g.clone(),
                    h1: keys.local_elgamal_pubkey.h.clone(),
                    g2: c_n.c1.clone(),
                    h2: c_n_1_sk1.clone(),
                };

                let ddh_witness = DDHWitness {
                    x: keys.private.sk.x.clone(),
                };
                let ddh_proof = DDHProof::prove(&ddh_witness, &ddh_statement);

                // full decryption + check that g^n = g^n
                let key = BigInt::mod_mul(
                    &c_n_1_sk1,
                    &party_two_ep_first_message.c_n_1_sk2,
                    &keys.joint_elgamal_pubkey.pp.p,
                );
                let key_inv = BigInt::mod_inv(&key, &keys.joint_elgamal_pubkey.pp.p);
                let g_n = BigInt::mod_mul(&key_inv, &c_n.c2, &keys.joint_elgamal_pubkey.pp.p);
                let g_n_tilde = BigInt::mod_pow(
                    &keys.joint_elgamal_pubkey.pp.g,
                    &bi_prime_n_tilde,
                    &keys.joint_elgamal_pubkey.pp.p,
                );
                match g_n == g_n_tilde {
                    true => Ok(PartyOneElgamalProductSecondMsg {
                        c_n_1_sk1,
                        ddh_proof,
                    }),
                    false => Err(TwoPartyRSAError::BiPrimesNotEqual),
                }
            }
            false => Err(TwoPartyRSAError::InvalidElGamalMul),
        }
    }
}

impl PartyOneBiPrimalityTest {
    // This function generates joint pubic randomness for gamma and h = ax + b (in TN).
    // We do this by hashing the candidate N together with the joint elgamal key and a seed
    // We next non interactively compute gamma_0 and u_0 (see [BF01]) together with pi_eq
    pub fn compute(
        n: &BigInt,
        p: &PartyOneCandidateWitness,
        q: &PartyOneCandidateWitness,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        keys: &PartyOneKeySetup,
        seed: &BigInt,
    ) -> PartyOneBiPrimalityTest {
        let four = BigInt::from(4);
        let (gamma, h) =
            compute_randomness_for_biprimality_test(&n, &keys.joint_elgamal_pubkey.h, &seed);

        //compute e0:
        let c_p0_plus_q0 = ExponentElGamal::add(
            &ciphertext_pair_p_candidate.c0,
            &ciphertext_pair_q_candidate.c0,
        )
        .unwrap();
        let c_minus_p0_plus_q0 = ExponentElGamal::mul(&c_p0_plus_q0, &(-BigInt::one()));
        // we use a fixed randomness
        let c_n_plus_one = ExponentElGamal::encrypt_from_predefined_randomness(
            &((n + BigInt::one()).modulus(&keys.joint_elgamal_pubkey.pp.q)),
            &keys.joint_elgamal_pubkey,
            &BigInt::from(2),
        )
        .unwrap();
        let c_n_minus_p0_plus_q0_plus_one =
            ExponentElGamal::add(&c_n_plus_one, &c_minus_p0_plus_q0).unwrap();
        let four_inv = four.invert(&keys.joint_elgamal_pubkey.pp.q).unwrap();
        let e_0 = ExponentElGamal::mul(&c_n_minus_p0_plus_q0_plus_one, &four_inv);

        let r_e_0_four: BigInt = BigInt::mod_add(
            &BigInt::from(2),
            &BigInt::mod_sub(
                &BigInt::zero(),
                &(&p.r_0 + &q.r_0),
                &keys.joint_elgamal_pubkey.pp.q,
            ),
            &keys.joint_elgamal_pubkey.pp.q,
        );
        let r_e_0 = BigInt::mod_mul(&r_e_0_four, &four_inv, &keys.joint_elgamal_pubkey.pp.q);
        let n_minus_p0_plus_q0_plus_one_div_four =
            (n + BigInt::one() - &p.p_0 - &q.p_0).div_floor(&four);
        let gamma_0 = BigInt::mod_pow(&gamma, &n_minus_p0_plus_q0_plus_one_div_four, n);

        let n_plus_p0_plus_q0_plus_one: BigInt = n + BigInt::one() + (&p.p_0 + &q.p_0);
        let u1 = TN::pow(&h, &n_plus_p0_plus_q0_plus_one, n);

        let gamma_eq_witness = EqWitness {
            x: n_minus_p0_plus_q0_plus_one_div_four.clone(),
            r: r_e_0.clone(),
        };

        let gamma_eq_statement = EqStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: gamma.clone(),
            h_prime: gamma_0.clone(),
            n: n.clone(),
            ciphertext: e_0,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let eq_proof = EqProof::prove(&gamma_eq_statement, &gamma_eq_witness).unwrap();

        // repeat the proof but for u1:
        let c_n_plus_1_plus_q0_plus_p0 =
            ExponentElGamal::add(&c_p0_plus_q0, &c_n_plus_one).unwrap();
        let r_c_n_plus_1_plus_q0_plus_p0: BigInt = BigInt::mod_add(
            &BigInt::from(2),
            &(&p.r_0 + &q.r_0),
            &keys.joint_elgamal_pubkey.pp.q,
        );

        let h_eq_witness_tn = EqWitnessTN {
            x: n_plus_p0_plus_q0_plus_one.clone(),
            r: r_c_n_plus_1_plus_q0_plus_p0.clone(),
        };

        let h_eq_statement_tn = EqStatementTN {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: h.clone(),
            h_prime: u1.clone(),
            n: n.clone(),
            ciphertext: c_n_plus_1_plus_q0_plus_p0,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let eq_proof_tn = EqProofTN::prove(&h_eq_statement_tn, &h_eq_witness_tn).unwrap();

        return PartyOneBiPrimalityTest {
            gamma_0,
            u1,
            eq_proof,
            eq_proof_tn,
        };
    }

    pub fn verify(
        &self,
        n: &BigInt,
        ciphertext_pair_p_candidate: &CiphertextPair,
        ciphertext_pair_q_candidate: &CiphertextPair,
        party_two_biprime_test: &PartyTwoBiPrimalityTest,
        seed: &BigInt,
        keys: &PartyOneKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        let four = BigInt::from(4);
        let (gamma, h) =
            compute_randomness_for_biprimality_test(&n, &keys.joint_elgamal_pubkey.h, &seed);

        let c_p1_plus_q1 = ExponentElGamal::add(
            &ciphertext_pair_p_candidate.c1,
            &ciphertext_pair_q_candidate.c1,
        )
        .unwrap();
        let c_minus_p1_plus_q1 = ExponentElGamal::mul(&c_p1_plus_q1, &(-BigInt::one()));
        let four_inv = four.invert(&keys.joint_elgamal_pubkey.pp.q).unwrap();
        let e_1 = ExponentElGamal::mul(&c_minus_p1_plus_q1, &four_inv);

        let gamma_eq_statement = EqStatement {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: gamma.clone(),
            h_prime: party_two_biprime_test.gamma_1.clone(),
            n: n.clone(),
            ciphertext: e_1,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        let h_eq_statement_tn = EqStatementTN {
            pk: keys.joint_elgamal_pubkey.clone(),
            h: h.clone(),
            h_prime: party_two_biprime_test.u2.clone(),
            n: n.clone(),
            ciphertext: c_p1_plus_q1,
            sec_param: SEC_PARAM,
            kapa: 100,
        };

        println!("test1 {:?}", party_two_biprime_test
            .eq_proof
            .verify(&gamma_eq_statement)
            .is_ok());
        println!("test2 {:?}", party_two_biprime_test
            .eq_proof_tn
            .verify(&h_eq_statement_tn)
            .is_ok());
        match party_two_biprime_test
            .eq_proof
            .verify(&gamma_eq_statement)
            .is_ok()
            && party_two_biprime_test
                .eq_proof_tn
                .verify(&h_eq_statement_tn)
                .is_ok()
        {
            true => {
                let gamma_test = BigInt::mod_mul(&self.gamma_0, &party_two_biprime_test.gamma_1, n);
                let h_test = TN::mul(&self.u1, &party_two_biprime_test.u2, n);

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



impl PartyOneCandidateGenerationSemiHonest {
    pub fn generate_shares_of_candidate_semi_honest(
        keys: &PartyOneKeySetup,
    ) -> (
        PartyOneCandidateWitness,
        PartyOneCandidateGenerationFirstMsgSemiHonest,
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
            PartyOneCandidateWitness {
                p_0: p_i,
                r_0: r_i,
                r_0_paillier: BigInt::zero(),
            },
            PartyOneCandidateGenerationFirstMsgSemiHonest {
                c_i,
            },
        )
    }


    pub fn generate_shares_of_candidate_semi_honest_inject(
        keys: &PartyOneKeySetup,
        prime_share: &BigInt,
    ) -> (
        PartyOneCandidateWitness,
        PartyOneCandidateGenerationFirstMsgSemiHonest,
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
            PartyOneCandidateWitness {
                p_0: p_i.clone(),
                r_0: r_i,
                r_0_paillier: BigInt::zero(),
            },
            PartyOneCandidateGenerationFirstMsgSemiHonest {
                c_i,
            },
        )
    }



    pub fn verify_party_two_first_message_and_normalize_ciphertexts_semi_honest(
        keys: &PartyOneKeySetup,
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
        keys: &PartyOneKeySetup,
        c: &CiphertextPair,
        w: &PartyOneCandidateWitness,
    ) -> Result<PartyOneCandidateGenerationSecondMsgSemiHonest, TwoPartyRSAError> {
        // update witness:
        let p_0 = BigInt::mod_add(
            &BigInt::mod_mul(&w.p_0, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q),
            &BigInt::from(3),
            &keys.joint_elgamal_pubkey.pp.q,
        );
        let r_0 = BigInt::mod_mul(&w.r_0, &BigInt::from(4), &keys.joint_elgamal_pubkey.pp.q);

        let p_0_mod_alpha = p_0.mod_floor(alpha);
        let r_0_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let c_0_alpha = ExponentElGamal::encrypt_from_predefined_randomness(
            &p_0_mod_alpha,
            &keys.joint_elgamal_pubkey,
            &r_0_alpha,
        )
            .unwrap();


        Ok(PartyOneCandidateGenerationSecondMsgSemiHonest {
            c_0_alpha,
        })

    }


    pub fn verify_party_two_second_message_and_partial_decrypt_semi_honest(
        party_one_second_message: &PartyOneCandidateGenerationSecondMsgSemiHonest,
        party_two_second_message: &PartyTwoCandidateGenerationSecondMsgSemiHonest,
        alpha: &BigInt,
        keys: &PartyOneKeySetup,
        c: &CiphertextPair,
    ) -> Result<
        (
            PartyOneCandidateGenerationThirdMsgSemiHonest,
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
        let enc_minus_alpha = ExponentElGamal::mul(&enc_alpha, &(-BigInt::one()));
        let c_alpha_tilde = ExponentElGamal::add(&c_alpha, &enc_minus_alpha).unwrap();

        // we raise each ciphertext with a secret random number
        let r_alpha = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);
        let r_alpha_tilde = BigInt::sample_below(&keys.joint_elgamal_pubkey.pp.q);

        let c_alpha_random = ExponentElGamal::mul(&c_alpha, &r_alpha);
        let c_alpha_tilde_random = ExponentElGamal::mul(&c_alpha_tilde, &r_alpha_tilde);

        // we use proof of DDH to prove to counter party that c_alpha_random = c_alpha ^r and same for c_alpha_tilde


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
            PartyOneCandidateGenerationThirdMsgSemiHonest {

                c_alpha_random,
                c_alpha_tilde_random,
                partial_dec_c_alpha: dec_key_alpha,
                partial_dec_c_alpha_tilde: dec_key_alpha_tilde,

            },
            c_alpha,
            c_alpha_tilde,
        ))
    }

    pub fn verify_party_two_third_message_full_decrypt_and_conclude_division_semi_honest(
        c_alpha: &ElGamalCiphertext,
        c_alpha_tilde: &ElGamalCiphertext,
        party_two_third_message: &PartyTwoCandidateGenerationThirdMsgSemiHonest,
        keys: &PartyOneKeySetup,
    ) -> Result<bool, TwoPartyRSAError> {
        // check that the randomization of the ciphertexts was done properly:


        // full decryption
        let dec_key_alpha = BigInt::mod_pow(
            &party_two_third_message.c_alpha_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde = BigInt::mod_pow(
            &party_two_third_message.c_alpha_tilde_random.c1,
            &keys.private.sk.x,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_full = BigInt::mod_mul(
            &dec_key_alpha,
            &party_two_third_message.partial_dec_c_alpha,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let dec_key_alpha_tilde_full = BigInt::mod_mul(
            &dec_key_alpha_tilde,
            &party_two_third_message.partial_dec_c_alpha_tilde,
            &keys.joint_elgamal_pubkey.pp.p,
        );

        let dec_key_alpha_full_inv =
            BigInt::mod_inv(&dec_key_alpha_full, &keys.joint_elgamal_pubkey.pp.p);
        let dec_key_alpha_tilde_full_inv =
            BigInt::mod_inv(&dec_key_alpha_tilde_full, &keys.joint_elgamal_pubkey.pp.p);

        let test1 = BigInt::mod_mul(
            &party_two_third_message.c_alpha_random.c2,
            &dec_key_alpha_full_inv,
            &keys.joint_elgamal_pubkey.pp.p,
        );
        let test2 = BigInt::mod_mul(
            &party_two_third_message.c_alpha_tilde_random.c2,
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