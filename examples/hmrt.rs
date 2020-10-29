use curv::BigInt;
use elgamal::prime::is_prime;
use vice_city::protocols::two_party_rsa::hmrt::party_one::PartyOneBiPrimalityTest;
use vice_city::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateGeneration;
use vice_city::protocols::two_party_rsa::hmrt::party_one::PartyOneCandidateWitness;
use vice_city::protocols::two_party_rsa::hmrt::party_one::PartyOneComputeProduct;
use vice_city::protocols::two_party_rsa::hmrt::party_one::PartyOneKeySetup;
use vice_city::protocols::two_party_rsa::hmrt::party_two::PartyTwoBiPrimalityTest;
use vice_city::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateGeneration;
use vice_city::protocols::two_party_rsa::hmrt::party_two::PartyTwoCandidateWitness;
use vice_city::protocols::two_party_rsa::hmrt::party_two::PartyTwoComputeProduct;
use vice_city::protocols::two_party_rsa::hmrt::party_two::PartyTwoKeySetup;
use vice_city::utlities::SMALL_PRIMES;
//use rayon::prelude::*;
use elgamal::rfc7919_groups::SupportedGroups;
use elgamal::ElGamalKeyPair;
use elgamal::ElGamalPP;
use elgamal::ExponentElGamal;
use std::time::Instant;
use vice_city::protocols::two_party_rsa::hmrt::CiphertextPair;
use vice_city::utlities::trial_div_pub;

const PRIME_CANDIDATES: usize = 700;
const B: usize = 11;
const C: usize = 3000; //15000;
const L: usize = 2;

// total number of rounds is 8 (given that for each round we aggragate enough messages of the same type)
fn main() {
    println!("START");

    // initalize
    let mut p1 = PartyOneCandidateWitness {
        p_0: BigInt::zero(),
        r_0: BigInt::zero(),
        r_0_paillier: BigInt::zero(),
    };
    let mut p2 = PartyTwoCandidateWitness {
        p_1: BigInt::zero(),
        r_1: BigInt::zero(),
    };
    let mut q1 = PartyOneCandidateWitness {
        p_0: BigInt::zero(),
        r_0: BigInt::zero(),
        r_0_paillier: BigInt::zero(),
    };
    let mut q2 = PartyTwoCandidateWitness {
        p_1: BigInt::zero(),
        r_1: BigInt::zero(),
    };
    let mut p1_vec = Vec::new();
    let mut p2_vec = Vec::new();
    let mut q1_vec = Vec::new();
    let mut q2_vec = Vec::new();
    let party_one_keys;
    let party_two_keys;
    let mut party_one_td_first_message;
    let mut party_two_td_first_message;
    let pp = ElGamalPP::generate_from_rfc7919(SupportedGroups::FFDHE2048);
    let keypair = ElGamalKeyPair::generate(&pp);
    let mut party_one_ciphertext_pair_p = CiphertextPair {
        c0: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
        c1: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
    };
    let mut party_one_ciphertext_pair_q = CiphertextPair {
        c0: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
        c1: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
    };
    let mut party_two_ciphertext_pair_p = CiphertextPair {
        c0: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
        c1: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
    };
    let mut party_two_ciphertext_pair_q = CiphertextPair {
        c0: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
        c1: ExponentElGamal::encrypt(&BigInt::one(), &keypair.pk).unwrap(),
    };
    let mut party_one_ciphertext_pair_p_vec = Vec::new();
    let mut party_one_ciphertext_pair_q_vec = Vec::new();
    let mut party_two_ciphertext_pair_p_vec = Vec::new();
    let mut party_two_ciphertext_pair_q_vec = Vec::new();

    let protocol_start = Instant::now();

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

    party_one_keys = party_one_key_setup_result.unwrap();
    party_two_keys = party_two_key_setup_result.unwrap();

    let mut start;
    start = Instant::now();

    let mut ctr;
    println!("KEYGEN DONE");

    let mut ctr2 = 0;

    // generating primes (can be run in parallel ) total of 4 rounds
    ctr = 0;
    for _ in 0..PRIME_CANDIDATES {
        ctr2 = ctr2 + 1;
        ctr = ctr + 1;

        // first p :
        let res = PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);
        p1 = res.0;
        party_one_td_first_message = res.1;

        let res = PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);
        p2 = res.0;
        party_two_td_first_message = res.1;
        let party_one_first_message_res =
            PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
                &party_one_keys,
                &party_one_td_first_message,
                &party_two_td_first_message,
            );
        party_one_ciphertext_pair_p = party_one_first_message_res.expect("");

        let party_two_first_message_res =
            PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
                &party_two_keys,
                &party_one_td_first_message,
                &party_two_td_first_message,
            );
        party_two_ciphertext_pair_p = party_two_first_message_res.expect("");

        // Pre sieving :
        // pick alpha in B :
        let mut b = 0;
        while b < B {
            let alpha = BigInt::from(SMALL_PRIMES[b]);

            let party_one_td_second_message =
                PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_p,
                    &p1,
                )
                .expect("");

            let party_two_td_second_message =
                PartyTwoCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_two_keys,
                    &party_two_ciphertext_pair_p,
                    &p2,
                )
                .expect("");

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
                ).expect("");

            let party_two_td_result = PartyTwoCandidateGeneration::verify_party_one_third_message_full_decrypt_and_conclude_division(
                    &party_two_c_alpha,
                    &party_two_c_alpha_tilde,
                    &party_one_td_third_message,
                    &party_two_keys,
                ).expect("");

            // test
            if party_one_td_result == false {
                break;
            }
            if party_two_td_result == false {
                break;
            }
            b = b + 1;
        }
        if b < B {
            continue;
        }
        // move on to next .
        else {
            p1_vec.push(p1.clone());
            p2_vec.push(p2.clone());
            party_one_ciphertext_pair_p_vec.push(party_one_ciphertext_pair_p.clone());
            party_two_ciphertext_pair_p_vec.push(party_two_ciphertext_pair_p.clone());
            // debug
            let p = (&p1.p_0 + &p2.p_1) * BigInt::from(4) + BigInt::from(3);
            if is_prime(&p) {
                println!("{:?} is potential p prime", ctr2.clone());
                continue;
            } else {
                continue;
            }
        }
    }

    ctr = 0;
    ctr2 = 0;
    println!("p duration: {:?}", start.elapsed());
    start = Instant::now();

    // now for q
    for _ in 0..PRIME_CANDIDATES {
        ctr2 = ctr2 + 1;
        ctr = ctr + 1;
        //   println!("counter p = {:?}", ctr.clone());
        //   println!("total tries p = {:?}", ctr2.clone());

        // generating two potential primes (can be run in parallel ) total of 4 rounds
        // first p :
        let res = PartyOneCandidateGeneration::generate_shares_of_candidate(&party_one_keys);
        q1 = res.0;
        party_one_td_first_message = res.1;

        let res = PartyTwoCandidateGeneration::generate_shares_of_candidate(&party_two_keys);
        q2 = res.0;
        party_two_td_first_message = res.1;
        let party_one_first_message_res =
            PartyOneCandidateGeneration::verify_party_two_first_message_and_normalize_ciphertexts(
                &party_one_keys,
                &party_one_td_first_message,
                &party_two_td_first_message,
            );
        party_one_ciphertext_pair_q = party_one_first_message_res.expect("");

        let party_two_first_message_res =
            PartyTwoCandidateGeneration::verify_party_one_first_message_and_normalize_ciphertexts(
                &party_two_keys,
                &party_one_td_first_message,
                &party_two_td_first_message,
            );
        party_two_ciphertext_pair_q = party_two_first_message_res.expect("");

        // Pre sieving :
        // pick alpha in B :
        start = Instant::now();
        let mut b = 0;
        while b < B {
            let alpha = BigInt::from(SMALL_PRIMES[b]);

            let party_one_td_second_message =
                PartyOneCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_one_keys,
                    &party_one_ciphertext_pair_q,
                    &q1,
                )
                .expect("");

            let party_two_td_second_message =
                PartyTwoCandidateGeneration::trial_division_prepare_c_alpha(
                    &alpha,
                    &party_two_keys,
                    &party_two_ciphertext_pair_q,
                    &q2,
                )
                .expect("");

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
                ).expect("");

            let party_two_td_result = PartyTwoCandidateGeneration::verify_party_one_third_message_full_decrypt_and_conclude_division(
                    &party_two_c_alpha,
                    &party_two_c_alpha_tilde,
                    &party_one_td_third_message,
                    &party_two_keys,
                ).expect("");

            // test
            if party_one_td_result == false {
                break;
            }
            if party_two_td_result == false {
                break;
            }
            b = b + 1;
        }
        if b < B {
            continue;
        }
        // move on to next .
        else {
            q1_vec.push(q1.clone());
            q2_vec.push(q2.clone());
            party_one_ciphertext_pair_q_vec.push(party_one_ciphertext_pair_q.clone());
            party_two_ciphertext_pair_q_vec.push(party_two_ciphertext_pair_q.clone());
            // debug
            let q = (&q1.p_0 + &q2.p_1) * BigInt::from(4) + BigInt::from(3);
            if is_prime(&q) {
                println!("{:?} is potential q prime", ctr2.clone());
                //
                continue;
            } else {
                continue;
            }
        }
    }
    println!("q duration: {:?}", start.elapsed());

    // debug:
    println!("p vector len : {:?}", p1_vec.len());
    println!("q vector len : {:?}", q1_vec.len());

    /////// compute and verify product  - total of two rounds
    //normalize secret shares

    let mut party_one_n_tilde = BigInt::zero();
    let mut party_two_n_tilde = BigInt::zero();


    let mut i = 0;
    let mut j = 0;
    let mut check_pi_not_prime = 0;

    loop {
        let mut flag = false;
        while i < p1_vec.len() {
            if j == q1_vec.len() {
                j = 0;
                check_pi_not_prime = 0;
            }
            while j < q1_vec.len() {
                println!("i: {:?}, j: {:?}", i.clone(), j.clone());
                p1 = PartyOneCandidateWitness {
                    p_0: &p1_vec[i].p_0 * BigInt::from(4) + &BigInt::from(3),
                    r_0: &p1_vec[i].r_0 * BigInt::from(4),
                    r_0_paillier: BigInt::zero(),
                };
                p2 = PartyTwoCandidateWitness {
                    p_1: &p2_vec[i].p_1 * BigInt::from(4),
                    r_1: &p2_vec[i].r_1 * BigInt::from(4),
                };
                q1 = PartyOneCandidateWitness {
                    p_0: &q1_vec[j].p_0 * BigInt::from(4) + &BigInt::from(3),
                    r_0: &q1_vec[j].r_0 * BigInt::from(4),
                    r_0_paillier: BigInt::zero(),
                };
                q2 = PartyTwoCandidateWitness {
                    p_1: &q2_vec[j].p_1 * BigInt::from(4),
                    r_1: &q2_vec[j].r_1 * BigInt::from(4),
                };

                let party_one_cp_first_message = PartyOneComputeProduct::send_candidate_ciphertexts(
                    &mut p1,
                    &mut q1,
                    &party_one_keys,
                );

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

                party_two_n_tilde = PartyTwoComputeProduct::verify_party_one_second_message(
                    &party_one_cp_first_message,
                    &party_two_cp_first_message,
                    &party_one_cp_second_message,
                    &party_two_keys,
                )
                .expect("");

                let party_one_ep_first_message =
                    PartyOneComputeProduct::compute_p0q0_elgamal_ciphertext(
                        &p1,
                        &q1,
                        &party_one_ciphertext_pair_p_vec[i],
                        &party_one_ciphertext_pair_q_vec[j],
                        &party_one_keys,
                    );

                let (party_two_ep_first_message, party_two_c_n) =
                PartyTwoComputeProduct::verify_party_one_elgamal_mult_compute_p0q0_elgamal_ciphertext(
                    &party_one_ep_first_message,
                    &p2,
                    &q2,
                    &party_two_ciphertext_pair_p_vec[i],
                    &party_two_ciphertext_pair_q_vec[j],
                    &party_two_keys,
                )
                    .expect("");

                let party_one_ep_second_message =
                    PartyOneComputeProduct::compute_elgamal_c_n_and_verify_biprime_correctness(
                        &party_one_ep_first_message,
                        &party_two_ep_first_message,
                        &party_one_ciphertext_pair_p_vec[i],
                        &party_one_ciphertext_pair_q_vec[j],
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

                //// trial division for N_tilde (done locally by by both parties)
                if trial_div_pub(B, C, &party_one_cp_second_message.n_tilde).unwrap() {
                    //
                    flag = true;
                    check_pi_not_prime = 0;

                    party_one_ciphertext_pair_p = party_one_ciphertext_pair_p_vec[i].clone();
                    party_one_ciphertext_pair_q = party_one_ciphertext_pair_q_vec[j].clone();
                    party_two_ciphertext_pair_p = party_two_ciphertext_pair_p_vec[i].clone();
                    party_two_ciphertext_pair_q = party_two_ciphertext_pair_q_vec[j].clone();
                    party_one_n_tilde = party_one_cp_second_message.n_tilde.clone();
                    j = j + 1;
                    break;
                } else {
                    check_pi_not_prime = check_pi_not_prime + 1;
                    if check_pi_not_prime == 20 {
                        check_pi_not_prime = 0;
                        j = 0;
                        break;
                    }
                }
                j = j + 1;
            }

            if flag {
                if j == q1_vec.len() {
                    i = i + 1
                }
                break;
            }
            i = i + 1;
        }

        ///// test biprimality . total of one round.

        if party_one_n_tilde == BigInt::zero() {
            continue;
        }
        let mut k = 1;
        while k < L {
            let seed = BigInt::from(k as i32);
            let party_one_biprime_test = PartyOneBiPrimalityTest::compute(
                &party_one_n_tilde,
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
                    &party_one_n_tilde,
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
            k = k + 1;
        }
        if k < L {
            // debug
            let p = &p1.p_0 + &p2.p_1;
            let q = &q1.p_0 + &q2.p_1;
            println!("is_prime(p): {:?}", is_prime(&p));
            println!("is_prime(q): {:?}", is_prime(&q));
            //
            // continue;
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
            println!("protocol duration: {:?}", protocol_start.elapsed());
            //break;
            return;
        }
    }
}
