use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneBiPrimalityTest;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGeneration;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateWitness;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneComputeProduct;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneKeySetup;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoBiPrimalityTest;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGeneration;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateWitness;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoComputeProduct;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoKeySetup;
use crate::utlities::SMALL_PRIMES;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::prime::is_prime;

#[test]
fn test_simulate_key_setup() {
    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    assert!(party_one_key_setup_result.is_ok());
    assert!(party_two_key_setup_result.is_ok());

    assert_eq!(
        party_one_key_setup_result.unwrap().joint_elgamal_pubkey,
        party_two_key_setup_result.unwrap().joint_elgamal_pubkey,
    );
}

#[test]
fn test_trial_division() {
    // key setup first
    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let (party_one_candidate_witness, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (party_two_candidate_witness, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair = party_two_first_message_res.expect("");

    // pick alpha in B :
    for i in 1..20 {
        let alpha = BigInt::from(SMALL_PRIMES[i]);
        println!("i: {:?}, alpha: {:?}", i.clone(), alpha.clone());

        let party_one_td_second_message_res =
            PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                &alpha,
                &party_one_keys,
                &party_one_ciphertext_pair,
                &party_one_candidate_witness,
            );
        let party_one_td_second_message;
        if party_one_td_second_message_res.is_err() {
            continue;
        } else {
            party_one_td_second_message = party_one_td_second_message_res.unwrap();
        }

        let party_two_td_second_message_res =
            PartyTwoCandidateGeneration::trial_division_prepare_c_alpha(
                &alpha,
                &party_two_keys,
                &party_two_ciphertext_pair,
                &party_two_candidate_witness,
            );

        let party_two_td_second_message;
        if party_two_td_second_message_res.is_err() {
            continue;
        } else {
            party_two_td_second_message = party_two_td_second_message_res.unwrap();
        }
        assert_eq!(party_one_ciphertext_pair, party_two_ciphertext_pair);

        let party_one_second_message_result =
            PartyOneCandidateGeneration::verify_party_two_second_message_and_partial_decrypt(
                &party_one_td_second_message,
                &party_two_td_second_message,
                &alpha,
                &party_one_keys,
                &party_one_ciphertext_pair,
            );
        let (party_one_td_third_message, party_one_c_alpha, party_one_c_alpha_tilde) =
            party_one_second_message_result.expect("");

        let party_two_second_message_result =
            PartyTwoCandidateGeneration::verify_party_one_second_message_and_partial_decrypt(
                &party_one_td_second_message,
                &party_two_td_second_message,
                &alpha,
                &party_two_keys,
                &party_two_ciphertext_pair,
            );
        let (party_two_td_third_message, party_two_c_alpha, party_two_c_alpha_tilde) =
            party_two_second_message_result.expect("");

        let party_one_td_result = PartyOneCandidateGeneration::verify_party_two_third_message_full_decrypt_and_conclude_division(
            &party_one_c_alpha,
            &party_one_c_alpha_tilde,
            &party_two_td_third_message,
            &party_one_keys,
        );

        let party_two_td_result = PartyTwoCandidateGeneration::verify_party_one_third_message_full_decrypt_and_conclude_division(
            &party_two_c_alpha,
            &party_two_c_alpha_tilde,
            &party_one_td_third_message,
            &party_two_keys,
        );

        assert!(party_one_td_result.is_ok());
        assert!(party_two_td_result.is_ok());

        assert_eq!(party_one_td_result.unwrap(), party_two_td_result.unwrap());
        let prime = &party_one_candidate_witness.p_0 + &party_two_candidate_witness.p_1;
        let prime_scaled = prime * BigInt::from(4) + BigInt::from(3);
        println!(
            "is_prime(p'): {:?},result: {:?}, gcd(alpha,p'): {:?}",
            is_prime(&prime_scaled),
            party_one_td_result.clone().unwrap(),
            BigInt::gcd(&alpha, &prime_scaled)
        );
        assert!(
            (party_one_td_result.unwrap() == true
                && BigInt::gcd(&alpha, &prime_scaled) == BigInt::one())
                || (party_one_td_result.unwrap() == false
                    && BigInt::gcd(&alpha, &prime_scaled) > BigInt::one())
        );
    }
    assert!(false);
}

#[test]
fn test_trial_division_for_prime() {
    // key setup first
    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let mut party_one_candidate_witness;
    let mut party_one_td_first_message;
    let mut party_two_candidate_witness;
    let mut party_two_td_first_message;
    loop {
        let res1 = PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);
        party_one_candidate_witness = res1.0;
        party_one_td_first_message = res1.1;
        let res2 = PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);
        party_two_candidate_witness = res2.0;
        party_two_td_first_message = res2.1;

        // TEST ONLY //
        let prime = &party_one_candidate_witness.p_0 + &party_two_candidate_witness.p_1;
        let prime_scaled = prime * BigInt::from(4) + BigInt::from(3);
        if is_prime(&prime_scaled) {
            break;
        }
    }
    //    //     //
    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair = party_two_first_message_res.expect("");

    // pick alpha in B :
    for i in 1..10 {
        let alpha = BigInt::from(SMALL_PRIMES[i]);
        println!("i: {:?}, alpha: {:?}", i.clone(), alpha.clone());

        let party_one_td_second_message_res =
            PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                &alpha,
                &party_one_keys,
                &party_one_ciphertext_pair,
                &party_one_candidate_witness,
            );
        let party_one_td_second_message;
        if party_one_td_second_message_res.is_err() {
            continue;
        } else {
            party_one_td_second_message = party_one_td_second_message_res.unwrap();
        }

        let party_two_td_second_message_res =
            PartyTwoCandidateGeneration::trial_division_prepare_c_alpha(
                &alpha,
                &party_two_keys,
                &party_two_ciphertext_pair,
                &party_two_candidate_witness,
            );

        let party_two_td_second_message;
        if party_two_td_second_message_res.is_err() {
            continue;
        } else {
            party_two_td_second_message = party_two_td_second_message_res.unwrap();
        }
        assert_eq!(party_one_ciphertext_pair, party_two_ciphertext_pair);

        let party_one_second_message_result =
            PartyOneCandidateGeneration::verify_party_two_second_message_and_partial_decrypt(
                &party_one_td_second_message,
                &party_two_td_second_message,
                &alpha,
                &party_one_keys,
                &party_one_ciphertext_pair,
            );
        let (party_one_td_third_message, party_one_c_alpha, party_one_c_alpha_tilde) =
            party_one_second_message_result.expect("");

        let party_two_second_message_result =
            PartyTwoCandidateGeneration::verify_party_one_second_message_and_partial_decrypt(
                &party_one_td_second_message,
                &party_two_td_second_message,
                &alpha,
                &party_two_keys,
                &party_two_ciphertext_pair,
            );
        let (party_two_td_third_message, party_two_c_alpha, party_two_c_alpha_tilde) =
            party_two_second_message_result.expect("");

        let party_one_td_result = PartyOneCandidateGeneration::verify_party_two_third_message_full_decrypt_and_conclude_division(
            &party_one_c_alpha,
            &party_one_c_alpha_tilde,
            &party_two_td_third_message,
            &party_one_keys,
        );

        let party_two_td_result = PartyTwoCandidateGeneration::verify_party_one_third_message_full_decrypt_and_conclude_division(
            &party_two_c_alpha,
            &party_two_c_alpha_tilde,
            &party_one_td_third_message,
            &party_two_keys,
        );

        assert!(party_one_td_result.is_ok());
        assert!(party_two_td_result.is_ok());

        assert_eq!(party_one_td_result.unwrap(), party_two_td_result.unwrap());
        let prime = &party_one_candidate_witness.p_0 + &party_two_candidate_witness.p_1;
        let prime_scaled = prime * BigInt::from(4) + BigInt::from(3);
        println!(
            "is_prime(p'): {:?},result: {:?}, gcd(alpha,p'): {:?}",
            is_prime(&prime_scaled),
            party_one_td_result.clone().unwrap(),
            BigInt::gcd(&alpha, &prime_scaled)
        );
        assert!(
            (party_one_td_result.unwrap() == true
                && BigInt::gcd(&alpha, &prime_scaled) == BigInt::one())
                || (party_one_td_result.unwrap() == false
                    && BigInt::gcd(&alpha, &prime_scaled) > BigInt::one())
        );
    }
    assert!(false);
}

#[test]
fn test_compute_product() {
    // we first generate some candidates (for this test - it doesn't matter if they are actually primes)

    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let (mut p1, _) = PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (p2, _) = PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let (mut q1, _) = PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (q2, _) = PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_cp_first_message =
        PartyOneComputeProduct::send_candidate_ciphertexts(&mut p1, &mut q1, &party_one_keys);

    let party_two_cp_first_message =
        PartyTwoComputeProduct::verify_party_one_first_message_compute_c_n_p0_q0(
            &party_one_cp_first_message,
            &p2,
            &q2,
            &party_two_keys,
        )
        .expect("");

    let party_one_cp_second_message =
        PartyOneComputeProduct::verify_party_two_first_message_decrypt_compute_n(
            &party_one_cp_first_message,
            &party_two_cp_first_message,
            &p1,
            &q1,
            &party_one_keys,
        )
        .expect("");

    let n_tilde = PartyTwoComputeProduct::verify_party_one_second_message(
        &party_one_cp_first_message,
        &party_two_cp_first_message,
        &party_one_cp_second_message,
        &party_two_keys,
    )
    .expect("");

    assert_eq!(n_tilde, (&p1.p_0 + &p2.p_1) * (&q1.p_0 + &q2.p_1))
}

#[test]
fn test_compute_and_verify_product() {
    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let (p1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (p2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_p = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_p = party_two_first_message_res.expect("");

    assert_eq!(party_one_ciphertext_pair_p, party_two_ciphertext_pair_p);

    let (q1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (q2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_q = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_q = party_two_first_message_res.expect("");
    assert_eq!(party_one_ciphertext_pair_q, party_two_ciphertext_pair_q);

    //normalize plaintext (just for the sake of test)
    let mut p1 = PartyOneCandidateWitness {
        p_0: &p1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &p1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let p2 = PartyTwoCandidateWitness {
        p_1: &p2.p_1 * BigInt::from(4),
        r_1: &p2.r_1 * BigInt::from(4),
    };
    let mut q1 = PartyOneCandidateWitness {
        p_0: &q1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &q1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let q2 = PartyTwoCandidateWitness {
        p_1: &q2.p_1 * BigInt::from(4),
        r_1: &q2.r_1 * BigInt::from(4),
    };

    let party_one_cp_first_message =
        PartyOneComputeProduct::send_candidate_ciphertexts(&mut p1, &mut q1, &party_one_keys);

    let party_two_cp_first_message =
        PartyTwoComputeProduct::verify_party_one_first_message_compute_c_n_p0_q0(
            &party_one_cp_first_message,
            &p2,
            &q2,
            &party_two_keys,
        )
        .expect("");

    let party_one_cp_second_message =
        PartyOneComputeProduct::verify_party_two_first_message_decrypt_compute_n(
            &party_one_cp_first_message,
            &party_two_cp_first_message,
            &p1,
            &q1,
            &party_one_keys,
        )
        .expect("");

    let party_two_n_tilde = PartyTwoComputeProduct::verify_party_one_second_message(
        &party_one_cp_first_message,
        &party_two_cp_first_message,
        &party_one_cp_second_message,
        &party_two_keys,
    )
    .expect("");

    let party_one_ep_first_message = PartyOneComputeProduct::compute_p0q0_elgamal_ciphertext(
        &p1,
        &q1,
        &party_one_ciphertext_pair_p,
        &party_one_ciphertext_pair_q,
        &party_one_keys,
    );

    let (party_two_ep_first_message, party_two_c_n) =
        PartyTwoComputeProduct::verify_party_one_elgamal_mult_compute_p0q0_elgamal_ciphertext(
            &party_one_ep_first_message,
            &p2,
            &q2,
            &party_two_ciphertext_pair_p,
            &party_two_ciphertext_pair_q,
            &party_two_keys,
        )
        .expect("");

    let party_one_ep_second_message =
        PartyOneComputeProduct::compute_elgamal_c_n_and_verify_biprime_correctness(
            &party_one_ep_first_message,
            &party_two_ep_first_message,
            &party_one_ciphertext_pair_p,
            &party_one_ciphertext_pair_q,
            &party_one_cp_second_message.n_tilde,
            &party_one_keys,
        )
        .expect("");

    PartyTwoComputeProduct::verify_decryption_and_biprime(
        &party_one_ep_second_message,
        &party_two_ep_first_message,
        &party_two_n_tilde,
        &party_two_c_n,
        &party_two_keys,
    )
    .expect("");
}

#[test]
fn test_biprimality() {
    // we first generate some candidates (for this test - it doesn't matter if they are actually primes)

    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let (p1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (p2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_p = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_p = party_two_first_message_res.expect("");

    assert_eq!(party_one_ciphertext_pair_p, party_two_ciphertext_pair_p);

    let (q1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);

    let (q2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_q = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_q = party_two_first_message_res.expect("");
    assert_eq!(party_one_ciphertext_pair_q, party_two_ciphertext_pair_q);

    //normalize plaintext (just for the sake of test)

    let p1 = PartyOneCandidateWitness {
        p_0: &p1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &p1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let p2 = PartyTwoCandidateWitness {
        p_1: &p2.p_1 * BigInt::from(4),
        r_1: &p2.r_1 * BigInt::from(4),
    };
    let q1 = PartyOneCandidateWitness {
        p_0: &q1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &q1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let q2 = PartyTwoCandidateWitness {
        p_1: &q2.p_1 * BigInt::from(4),
        r_1: &q2.r_1 * BigInt::from(4),
    };

    // we need p,q,N for this test
    let p = &p1.p_0 + &p2.p_1;
    let q = &q1.p_0 + &q2.p_1;
    let n: BigInt = &p * &q;

    let l = 4;
    let mut result_vec = Vec::new();
    for i in 1..l {
        let seed = BigInt::from(i);
        let party_one_biprime_test = PartyOneBiPrimalityTest::compute(
            &n,
            &p1,
            &q1,
            &party_one_ciphertext_pair_p,
            &party_one_ciphertext_pair_q,
            &party_one_keys,
            &seed,
        );

        let party_two_biprime_test = PartyTwoBiPrimalityTest::compute(
            &n,
            &p2,
            &q2,
            &party_two_ciphertext_pair_p,
            &party_two_ciphertext_pair_q,
            &party_two_keys,
            &seed,
        );

        let party_one_res = party_one_biprime_test.verify(
            &n,
            &party_one_ciphertext_pair_p,
            &party_one_ciphertext_pair_q,
            &party_two_biprime_test,
            &seed,
            &party_one_keys,
        );

        assert!(party_one_res.is_ok());
        let party_two_res = party_two_biprime_test.verify(
            &n,
            &party_two_ciphertext_pair_p,
            &party_two_ciphertext_pair_q,
            &party_one_biprime_test,
            &seed,
            &party_two_keys,
        );
        assert!(party_two_res.is_ok());
        assert_eq!(party_one_res.unwrap(), party_two_res.unwrap());
        result_vec.push(party_one_res.unwrap());
    }

    if is_prime(&p) && is_prime(&q) {
        assert!(result_vec.iter().all(|x| *x));
    } else {
        assert_eq!(result_vec.iter().all(|x| *x), false)
    }
}

#[test]
fn test_biprimality_for_p_q_primes() {
    // we first generate some candidates (for this test - it doesn't matter if they are actually primes)

    let (party_one_first_message, party_one_private) =
        PartyOneKeySetup::gen_local_keys_and_first_message_to_party_two();

    let (party_two_first_message, party_two_private) =
        PartyTwoKeySetup::gen_local_keys_and_first_message_to_party_one();

    let party_one_key_setup_result =
        PartyOneKeySetup::verify_party_two_first_message_and_output_party_one_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_one_private,
        );
    let party_two_key_setup_result =
        PartyTwoKeySetup::verify_party_one_first_message_and_output_party_two_keys(
            &party_one_first_message,
            &party_two_first_message,
            party_two_private,
        );

    let party_one_keys = party_one_key_setup_result.unwrap();
    let party_two_keys = party_two_key_setup_result.unwrap();

    let mut c = BigInt::sample(1000);
    c = c * BigInt::from(4) + BigInt::from(3);
    while !is_prime(&c) {
        c = BigInt::sample(1000);
        c = c * BigInt::from(4) + BigInt::from(3);
    }

    let c_scaled = (c - BigInt::from(3)).div_floor(&BigInt::from(4));
    let rand = BigInt::sample_below(&c_scaled);
    let p1 = &c_scaled - &rand;
    let p2 = rand;

    let mut d = BigInt::sample(1000);
    d = d * BigInt::from(4) + BigInt::from(3);
    while !is_prime(&d) {
        d = BigInt::sample(1000);
        d = d * BigInt::from(4) + BigInt::from(3);
    }

    let d_scaled = (d - BigInt::from(3)).div_floor(&BigInt::from(4));
    let rand = BigInt::sample_below(&d_scaled);
    let q1 = &d_scaled - &rand;
    let q2 = rand;

    let (p1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate_inject_test(&party_one_keys, p1);

    let (p2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate_inject_test(&party_two_keys, p2);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_p = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_p = party_two_first_message_res.expect("");

    assert_eq!(party_one_ciphertext_pair_p, party_two_ciphertext_pair_p);

    let (q1, party_one_td_first_message) =
        PartyOneCandidateGeneration::generate_shares_of_candidate_inject_test(&party_one_keys, q1);

    let (q2, party_two_td_first_message) =
        PartyTwoCandidateGeneration::generate_shares_of_candidate_inject_test(&party_two_keys, q2);

    let party_one_first_message_res =
        PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
            &party_one_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_one_ciphertext_pair_q = party_one_first_message_res.expect("");

    let party_two_first_message_res =
        PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
            &party_two_keys,
            &party_one_td_first_message,
            &party_two_td_first_message,
        );
    let party_two_ciphertext_pair_q = party_two_first_message_res.expect("");
    assert_eq!(party_one_ciphertext_pair_q, party_two_ciphertext_pair_q);

    //normalize plaintext (just for the sake of test)

    let p1 = PartyOneCandidateWitness {
        p_0: &p1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &p1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let p2 = PartyTwoCandidateWitness {
        p_1: &p2.p_1 * BigInt::from(4),
        r_1: &p2.r_1 * BigInt::from(4),
    };
    let q1 = PartyOneCandidateWitness {
        p_0: &q1.p_0 * BigInt::from(4) + &BigInt::from(3),
        r_0: &q1.r_0 * BigInt::from(4),
        r_0_paillier: BigInt::zero(),
    };
    let q2 = PartyTwoCandidateWitness {
        p_1: &q2.p_1 * BigInt::from(4),
        r_1: &q2.r_1 * BigInt::from(4),
    };

    // we need p,q,N for this test
    let p = &p1.p_0 + &p2.p_1;
    let q = &q1.p_0 + &q2.p_1;

    let n: BigInt = &p * &q;

    let l = 5;
    let mut result_vec = Vec::new();
    for i in 1..l {
        let seed = BigInt::from(i);
        let party_one_biprime_test = PartyOneBiPrimalityTest::compute(
            &n,
            &p1,
            &q1,
            &party_one_ciphertext_pair_p,
            &party_one_ciphertext_pair_q,
            &party_one_keys,
            &seed,
        );

        let party_two_biprime_test = PartyTwoBiPrimalityTest::compute(
            &n,
            &p2,
            &q2,
            &party_two_ciphertext_pair_p,
            &party_two_ciphertext_pair_q,
            &party_two_keys,
            &seed,
        );

        let party_one_res = party_one_biprime_test.verify(
            &n,
            &party_one_ciphertext_pair_p,
            &party_one_ciphertext_pair_q,
            &party_two_biprime_test,
            &seed,
            &party_one_keys,
        );

        assert!(party_one_res.is_ok());
        let party_two_res = party_two_biprime_test.verify(
            &n,
            &party_two_ciphertext_pair_p,
            &party_two_ciphertext_pair_q,
            &party_one_biprime_test,
            &seed,
            &party_two_keys,
        );
        assert!(party_two_res.is_ok());
        assert_eq!(party_one_res.unwrap(), party_two_res.unwrap());
        result_vec.push(party_one_res.unwrap());
        println!("result_vec {:?}", result_vec.clone());
    }

    if is_prime(&p) && is_prime(&q) {
        assert!(result_vec.iter().all(|x| *x));
    } else {
        println!("result_vec {:?}", result_vec.clone());
        assert_eq!(result_vec.iter().all(|x| *x), false)
    }

    assert!(false);
}
