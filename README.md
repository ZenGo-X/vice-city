# Two Party Distributed RSA Modulus Generation

The code in this library follows protocol 4 from [Efficient RSA Key Generation and Threshold Paillier in the Two-Party Setting](https://eprint.iacr.org/2011/494.pdf) together with insights from newer works ([1](https://eprint.iacr.org/2018/577.pdf), [2](https://eprint.iacr.org/2020/370.pdf), [3](https://eprint.iacr.org/2020/374)) and older work ([BF01](https://crypto.stanford.edu/~dabo/pubs/papers/sharing.ps)). The code heavily relies on the [zk-paillier](https://github.com/ZenGo-X/zk-paillier) and [rust-elgamal](https://github.com/ZenGo-X/rust-elgamal) libraries.

## Warnings
- Audit: The code is not audited
- Stability: Breaking changes are expected
- Performence: Producing an RSA biprime of sufficient length (2048bits) is extremely slow


## How to use this library and for what
Distributed RSA modulus makes sure that no single party knows the order of the RSA group generated from the bi-prime. Therefore such group can be used in applications where groups of unknown order are required (i.e. some [VDFs](https://eprint.iacr.org/2018/601.pdf)). Furthermore, Distributed RSA keys are useful building block for various threshold cryptosystems (i.e. [threshold ECDSA](https://eprint.iacr.org/2016/013.pdf)) and for general-purpose MPC ([DN03](https://iacr.org/archive/crypto2003/27290247/27290247.ps))

- The library contains an executable example: run it with the command: `cargo run --example hmrt --release` 
- There is an intergration test (under `protocols/two_party_rsa/hmrt/integration_test`) and tests for the specifics steps composing the protocol (key generation, trial-division, compute-product, biprime-test). It is recommended to follow the steps in the tests (note that network is not implemented yet).   


## Contact
Feel free to [reach out](mailto:omer@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.
