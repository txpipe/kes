# Key Evolving Signatures ![CI workflow](https://github.com/input-output-hk/kes/actions/workflows/ci.yml/badge.svg) ![crates.io](https://img.shields.io/crates/v/kes-summed-ed25519.svg) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

`kes-sumed-ed25519` is a pure rust implementation of Key Evolving Signatures, following the paper
from ["Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"](https://eprint.iacr.org/2001/034)
by Malkin, Micciancio and Miner. In particular, we implement the "sum" composition, from Section
3.1. As a depth zero signature algorithm we use Ed25519 using the `strict` verification criteria from
[`ed25519_dalek`](https://github.com/dalek-cryptography/ed25519-dalek), which is the same as currently
used in [libsodium](https://github.com/jedisct1/libsodium).

This library defines macros to generate KES algorithms with different depths. We currently expose KES
algorithms up to depth 7. However, if you require a higher depth key, feel free to open an
issue/PR.

## Library usage
This library exposes `SumXKes` for `X` in [2,7]. A KES algorithm with depth `X` can evolve the key
`2^X`. When a secret key is evolved, the old seed is overwritten with zeroes.

```rust
use kes_summed_ed25519::kes::Sum6Kes;
use kes_summed_ed25519::traits::{KesSig, KesSk};

fn main() {
    let (mut skey, pkey) = Sum6Kes::keygen(&mut [0u8; 32]);
    let dummy_message = b"tilin";
    let sigma = skey.sign(0, dummy_message);

    assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

    // Key can be updated 63 times
    for i in 0..63 {
        assert!(skey.update(i).is_ok());
    }
}
```

## Compatibility with Cardano
We provide two implementations of KES for compatibility with Cardano's blockchain. Cardano currently
uses `Sum6Kes`. However, that implementation is not optimal in what concerns signature size. Instead,
we provide implementation of `SumCompact6Kes`, which provides an asymptotic halving of the signature
size. We provide test vectors generated using Cardano's code to ensure that future changes in the
library will not lose compatibility with Cardano. These test vectors can be found in `./tests/data`,
and the tests can be found in `./tests/interoperability.rs`.

**Note**: secret keys of this crate are not compatible with KES keys as they are used in the
[cardano node](https://github.com/input-output-hk/cardano-node). In this crate we include the
period of the KES secret key as part of its structure, while the cardano implementation does not.
This decision is motivated by two reasons:
* It considerably simplifies the API and makes it more intuitive to use. Moreover, the period is
  a required knowledge to sign/update a skey, and we concluded that a secret key should contain it's
  period.
* Secret keys are not send through the wire, meaning that a node using this implementation will not
  need to be compatible with cardano node's serialisation. However, if for some reason one needs to
  serialise a cardano node serialised key for usage in this application (or vice-versa), one simply
  needs to add the period as a 32 bit number represented in 4 big endian bytes (or, vice-versa,
  remove the last 4 bytes from the serialised signature). An example of such a procedure can be found
  in the [interoperability](./tests/interoperability.rs) tests of this crate.

## Previous versions of the code
This repo is a copy and modification of
[kes-mmm-sumed25519](https://github.com/input-output-hk/kes-mmm-sumed25519). The old repo
remains unchanged for historical purposes.

## Disclaimer
This crate has not been audited. Use at your own risk.

## Contribution
Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be licensed
as above, without any additional terms or conditions.

## Command-Line

`kes-summed-ed25519` comes with a command-line interface for Linux. The command-line is self explanatory by using `--help` on various commands and sub-commands.

### How to randomly generate a 32-byte valid secret seed (<strong>seed.prv</strong>)

```console
$ cargo run --quiet -- -s ; echo
bf410498bcb54308b2f9483a488430610fb40e4dd7d84baa1bbb35174231b0e0
$ cargo run --quiet -- -s ; echo
76a0e64fb116d8dedde3d2d3de8c14a0c96d18b05ec7fa4e7e7c409df7985598
```

### How to randomly generate a 612-byte valid signing key (<strong>sk.prv</strong>)

```console
$ cargo run --quiet -- -k ; echo
2ad497b6916eeee80ad9684c7e84ecaa5a29b41b3fa9568c274f522701e3243bcb19f7e677655ef84055a8f18f5ac735e0740a5910dc13fd50858eee17bc8195b520a6ff1b26cb5981ede21e4424b95d08f5cb5ec778fad20ef0d2554fe494d89ee6bcdc03ac6cace7d3c090ec416b706792f6249d19d94c2e4ec6acaa38ebd7ba374ea697845d98bb514749e6c58ff4cd61047be72327ba531c1aef4e63329a2bf6529b0de0dfb4f03ff7ea33f3bc40b9153fccea8ee1a8da4d7d476ec58e889fca891f462876a41dfc2b8472a1e60d52b73598c73cfe25286bb90e01902551dab4c21f4b14a90b482e7d80366c75f97c7dc41b7fc57b76d404c2760d62a2cdd076099c58b8b09f774ea303471e0fdbeee594f8bc91fcf33290b1306cc369483147a6c79400feaa4ce0b71a48120f21962433c8850e9a5c3029817b829a84804ef17d293bc69ff7867e1de175bf2e138236f5ab6dd5825ce239e69cc34694e36a4dbe7b1821564e21bd3ffac2ec44eb05b1bc8ad5a9aed4142a463ae46970d25dfe7ac747f0924f777993e7bd3a5556ef6584d03535315be4c4a9d691159bb0a1355160d00798c5d93c8daffee3eb2b067cb99a20d5adb4f0dea9254fbd3c7e4fa53f73bf1faa689698ff1847ac3486922c362556747b487ee67d55fb34206f5f8bd617395fe6bed77c7cc98f1b0d848854411beab9876c6e15a23d1ca5f93d445d9a57bc7a5e9e870945f1b4e9b22e242c87e585930b41ed63f5ace2ed3f1fc4616161d7001711bc47785648c7608199edfc5a11a129cbe94757d1e4c5e8f7d8c06d391ad58ab1f8ddd9380f0646b702830a89a2b2d6592b4e26b4fa5157c200000000
$ cargo run --quiet -- -k ; echo
e3fb7b7a2113941ae4f0e0aa50f08d25afe0ddd31c17054e71d2d1189d1136aa10e30bdb561bb2a98f2029b735ecbaec47a99673e872a58447d9dad7039c826635448955c61483f61d2c1dd056c9bdddd06ad17e8a024e6f4a45056496884d338772f4bf6c23b645b1080859a45e61153b238cd6b648c275497dbae1980288559cb757a26a0d23b7c53784549634bedbeb4c2ab1b4c055f251621418ae7ea5cf89d9651a5ea9c02e0325eeeea398c2b509fb612358991db7ac6ecfcb3e39a107cd8302e6c8749b9f61822b765c28a9fa4b68fd1ac7e4bdc98f6e1d3ecbc451ca4d6e0225138ba366fc2c9b4ad9fb3ef6fdc64f3203d374912b3a88e3ab3a1121c5c73af5b1425641502a4eeeb4ce481a21b34dbb6680936651f72d220c098296169b46c5de4e14010db5ac46e55d440d69882a108f39360b3e1f7e43bde82299122b7a6a1ad536a720b2893e8db1ed3f8b47330faaa8c7d3b467169276e17ec565bff33a32646f9a557a3f97fd38456da7bfe33949212193871006e44b26c52444f29ecf82e19552584b2e0d9e29bdc8d2dc8b87f98ea3bccbad54770cb575a36322cb2799c8270fbb86c10ba8f7a0eeabf02194880c6fae8da0c6a155c6d686d390b12aa28303d682648c62805782d5ef0a7f9a4eb5278435b9d8e55b23af64f3da3ac210c15dd387542901fe63f9135347bee6caddf93acdccc498bd11d36b7118c866218dc13829044cd5e2dea572138acc37a811e1b8b32c251dc1ca2566f133ef8d1d06bd41a2466e8cf6ce37e3a2d05697bb9e7ed2a10b3d88619e9b76f2f81b6c8360bb743606a2ad346fcdb759db7580ffeb0f94a7c2771e8cd0e40c00000000
```

### How to derive a 612-byte valid signing key from a 32-byte secret seed (<strong>sk.prv</strong>)

```console
$ echo -n 7fe54ac4449ef108b4717620b36085f300de9758decd6ad240b24b37d3f3dfc5 | cargo run --quiet -- --derive_sk ; echo
60cb0d00b11878c25d9b906607bdad7dd79d732484bfaf48b043eb4c17bbd09d44e5e3031be8b67c0d25247c35d767fa5ad5266e3a54fb851f16e0cf8e84eabd9e7805d1c6f2e8f6a7546ba288952cd8b2f27532ed28ba0205aab0b2a0ce3b3fc4f63b08c1c325589d6faed23b315802a6cef82f68352a2116ff2755956258467a4b5aa8f157a6c683c8a4a9c1ac2b073eb8ea1b919e745de5d7d51a2f18c6e11bb6a2b5b9e3837cd0d5848a5db4aee7d2fdf7ab734833fbfe8c1470128fd5707b85710dddb4ebdc49eff82a74238c2e64a1e16585cb52a80c5fae6c3c592e3c9a06b0627b41b9bc7b6c514542c8ec5f85224798e39ea27f2c34c72ce925489eb8212f14e67fd788f49abfb950bd6d9c07ab3783ce86c9937dfa4fd333bd1f6e82478cfd5ad30773f4096b314e9bcfff8770052b2fe58547d03f6cd7848fe24f1efeeec17099b26058ac94fe54268472838da00da4154694380bdc8c6f9ee43103cdf0d93d54eb615e05a8ebeb9a95876b818e2f5522f8675cecead549dd13acaca314c9f01a556197bf93ece5b544a1ee136bc116412fd1ca51fe0874c2d8b4794e754cb8d73e8bfe7d21acab20b0707f2be54cd8f99bc568ccccfeebe3928810cc8840f62b3785f578a51f37f0756fe3ca43579e4d049ce9d5754e4e4ada908b0e063f3e52e24d1bee78f7cfab25b1bb867d562c93d53b0143ecc3b79924ea40087b687ede4d15a66c46d44a29002ecd9da6995f1d0b4e0a7be396f29e544b9a762b52d93e17818e396bd5192b9fae26f34dfdda3dbd7e666b0be11dce71cc083279b1e66d9913bd97c576143d3994a4374367380f8c8c784f62050622307000000000
```
