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
use curv::BigInt;
use elgamal::prime::is_prime;
use curv::arithmetic::{Zero, One, Integer};
use curv::arithmetic::Converter;

const B: usize = 10;
const L: usize = 2;

// total number of rounds is 8 (given that for each round we aggragate enough messages of the same type)
#[test]
fn integration_test() {
    // key setup - one round
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

    loop {
        // generating two potential primes (can be run in parallel ) total of 4 rounds
        // first p :

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

        // Pre sieving :
        // pick alpha in B :
        let mut b = 0;
        while b < B {
            let alpha = BigInt::from(SMALL_PRIMES[b]);

            let party_one_td_second_message_res =
                PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_p,
                    &p1,
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
                    &party_two_ciphertext_pair_p,
                    &p2,
                );

            let party_two_td_second_message;
            if party_two_td_second_message_res.is_err() {
                continue;
            } else {
                party_two_td_second_message = party_two_td_second_message_res.unwrap();
            }

            let party_one_second_message_result =
                PartyOneCandidateGeneration::verify_party_two_second_message_and_partial_decrypt(
                    &party_one_td_second_message,
                    &party_two_td_second_message,
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_p,
                );
            let (party_one_td_third_message, party_one_c_alpha, party_one_c_alpha_tilde) =
                party_one_second_message_result.expect("");

            let party_two_second_message_result =
                PartyTwoCandidateGeneration::verify_party_one_second_message_and_partial_decrypt(
                    &party_one_td_second_message,
                    &party_two_td_second_message,
                    &alpha,
                    &party_two_keys,
                    &party_two_ciphertext_pair_p,
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

            // test
            if party_one_td_result.unwrap() == false {
                break;
            }
            if party_two_td_result.unwrap() == false {
                break;
            }
            b = b + 1;
        }
        if b < B {
            continue;
        } // move on to next pair.

        // now for q

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

        let mut b = 0;
        while b < B {
            let alpha = BigInt::from(SMALL_PRIMES[b]);

            let party_one_td_second_message_res =
                PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_q,
                    &q1,
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
                    &party_two_ciphertext_pair_q,
                    &q2,
                );

            let party_two_td_second_message;
            if party_two_td_second_message_res.is_err() {
                continue;
            } else {
                party_two_td_second_message = party_two_td_second_message_res.unwrap();
            }

            let party_one_second_message_result =
                PartyOneCandidateGeneration::verify_party_two_second_message_and_partial_decrypt(
                    &party_one_td_second_message,
                    &party_two_td_second_message,
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_q,
                );
            let (party_one_td_third_message, party_one_c_alpha, party_one_c_alpha_tilde) =
                party_one_second_message_result.expect("");

            let party_two_second_message_result =
                PartyTwoCandidateGeneration::verify_party_one_second_message_and_partial_decrypt(
                    &party_one_td_second_message,
                    &party_two_td_second_message,
                    &alpha,
                    &party_two_keys,
                    &party_two_ciphertext_pair_q,
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

            // test
            if party_one_td_result.unwrap() == false {
                break;
            }
            if party_two_td_result.unwrap() == false {
                break;
            }
            b = b + 1;
        }
        if b < B {
            continue;
        } // move on to next pair.

        /////// compute and verify product  - total of two rounds
        //normalize secret shares

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

        ///// test biprimality . total of one round.

        let mut i = 1;
        while i < L {
            let seed = BigInt::from(i as i32);
            let party_one_biprime_test = PartyOneBiPrimalityTest::compute(
                &party_one_cp_second_message.n_tilde,
                &p1,
                &q1,
                &party_one_ciphertext_pair_p,
                &party_one_ciphertext_pair_q,
                &party_one_keys,
                &seed,
            );

            let party_two_biprime_test = PartyTwoBiPrimalityTest::compute(
                &party_two_n_tilde,
                &p2,
                &q2,
                &party_two_ciphertext_pair_p,
                &party_two_ciphertext_pair_q,
                &party_two_keys,
                &seed,
            );

            let party_one_res = party_one_biprime_test
                .verify(
                    &party_one_cp_second_message.n_tilde,
                    &party_one_ciphertext_pair_p,
                    &party_one_ciphertext_pair_q,
                    &party_two_biprime_test,
                    &seed,
                    &party_one_keys,
                )
                .expect("");

            if party_one_res == false {
                break;
            }
            let party_two_res = party_two_biprime_test
                .verify(
                    &party_two_n_tilde,
                    &party_two_ciphertext_pair_p,
                    &party_two_ciphertext_pair_q,
                    &party_one_biprime_test,
                    &seed,
                    &party_two_keys,
                )
                .expect("");
            if party_two_res == false {
                break;
            }
            i = i + 1;
        }
        if i < L {
            continue;
        } else {
            // we found our N
            let p = &p1.p_0 + &p2.p_1;
            let q = &q1.p_0 + &q2.p_1;

            let n: BigInt = &p * &q;
            println!("p: {:?}", p.clone().to_str_radix(16));
            println!("q: {:?}", q.clone().to_str_radix(16));
            println!("n: {:?}", n.clone().to_str_radix(16));
            println!("is_prime(p): {:?}", is_prime(&p));
            println!("is_prime(q): {:?}", is_prime(&q));
            assert!(false);
            return;
        }
    }
}
