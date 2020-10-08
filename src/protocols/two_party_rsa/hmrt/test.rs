use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGeneration;
use crate::protocols::two_party_rsa::hmrt::party_one::PartyOneKeySetup;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGeneration;
use crate::protocols::two_party_rsa::hmrt::party_two::PartyTwoKeySetup;
use crate::utlities::SMALL_PRIMES;
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
