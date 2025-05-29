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
$ cargo run --quiet -- --generate_seed ; echo
bf410498bcb54308b2f9483a488430610fb40e4dd7d84baa1bbb35174231b0e0
$ cargo run --quiet -- --generate_seed ; echo
76a0e64fb116d8dedde3d2d3de8c14a0c96d18b05ec7fa4e7e7c409df7985598
```

### How to randomly generate a 612-byte valid signing key (<strong>sk.prv</strong>)

```console
$ cargo run --quiet -- --generate_sk ; echo
2ad497b6916eeee80ad9684c7e84ecaa5a29b41b3fa9568c274f522701e3243bcb19f7e677655ef84055a8f18f5ac735e0740a5910dc13fd50858eee17bc8195b520a6ff1b26cb5981ede21e4424b95d08f5cb5ec778fad20ef0d2554fe494d89ee6bcdc03ac6cace7d3c090ec416b706792f6249d19d94c2e4ec6acaa38ebd7ba374ea697845d98bb514749e6c58ff4cd61047be72327ba531c1aef4e63329a2bf6529b0de0dfb4f03ff7ea33f3bc40b9153fccea8ee1a8da4d7d476ec58e889fca891f462876a41dfc2b8472a1e60d52b73598c73cfe25286bb90e01902551dab4c21f4b14a90b482e7d80366c75f97c7dc41b7fc57b76d404c2760d62a2cdd076099c58b8b09f774ea303471e0fdbeee594f8bc91fcf33290b1306cc369483147a6c79400feaa4ce0b71a48120f21962433c8850e9a5c3029817b829a84804ef17d293bc69ff7867e1de175bf2e138236f5ab6dd5825ce239e69cc34694e36a4dbe7b1821564e21bd3ffac2ec44eb05b1bc8ad5a9aed4142a463ae46970d25dfe7ac747f0924f777993e7bd3a5556ef6584d03535315be4c4a9d691159bb0a1355160d00798c5d93c8daffee3eb2b067cb99a20d5adb4f0dea9254fbd3c7e4fa53f73bf1faa689698ff1847ac3486922c362556747b487ee67d55fb34206f5f8bd617395fe6bed77c7cc98f1b0d848854411beab9876c6e15a23d1ca5f93d445d9a57bc7a5e9e870945f1b4e9b22e242c87e585930b41ed63f5ace2ed3f1fc4616161d7001711bc47785648c7608199edfc5a11a129cbe94757d1e4c5e8f7d8c06d391ad58ab1f8ddd9380f0646b702830a89a2b2d6592b4e26b4fa5157c200000000
$ cargo run --quiet -- --generate_sk ; echo
e3fb7b7a2113941ae4f0e0aa50f08d25afe0ddd31c17054e71d2d1189d1136aa10e30bdb561bb2a98f2029b735ecbaec47a99673e872a58447d9dad7039c826635448955c61483f61d2c1dd056c9bdddd06ad17e8a024e6f4a45056496884d338772f4bf6c23b645b1080859a45e61153b238cd6b648c275497dbae1980288559cb757a26a0d23b7c53784549634bedbeb4c2ab1b4c055f251621418ae7ea5cf89d9651a5ea9c02e0325eeeea398c2b509fb612358991db7ac6ecfcb3e39a107cd8302e6c8749b9f61822b765c28a9fa4b68fd1ac7e4bdc98f6e1d3ecbc451ca4d6e0225138ba366fc2c9b4ad9fb3ef6fdc64f3203d374912b3a88e3ab3a1121c5c73af5b1425641502a4eeeb4ce481a21b34dbb6680936651f72d220c098296169b46c5de4e14010db5ac46e55d440d69882a108f39360b3e1f7e43bde82299122b7a6a1ad536a720b2893e8db1ed3f8b47330faaa8c7d3b467169276e17ec565bff33a32646f9a557a3f97fd38456da7bfe33949212193871006e44b26c52444f29ecf82e19552584b2e0d9e29bdc8d2dc8b87f98ea3bccbad54770cb575a36322cb2799c8270fbb86c10ba8f7a0eeabf02194880c6fae8da0c6a155c6d686d390b12aa28303d682648c62805782d5ef0a7f9a4eb5278435b9d8e55b23af64f3da3ac210c15dd387542901fe63f9135347bee6caddf93acdccc498bd11d36b7118c866218dc13829044cd5e2dea572138acc37a811e1b8b32c251dc1ca2566f133ef8d1d06bd41a2466e8cf6ce37e3a2d05697bb9e7ed2a10b3d88619e9b76f2f81b6c8360bb743606a2ad346fcdb759db7580ffeb0f94a7c2771e8cd0e40c00000000
```

### How to derive a 612-byte signing key from a 32-byte secret seed (<strong>sk.prv</strong>)

```console
$ echo -n 7fe54ac4449ef108b4717620b36085f300de9758decd6ad240b24b37d3f3dfc5 | cargo run --quiet -- --derive_sk ; echo
60cb0d00b11878c25d9b906607bdad7dd79d732484bfaf48b043eb4c17bbd09d44e5e3031be8b67c0d25247c35d767fa5ad5266e3a54fb851f16e0cf8e84eabd9e7805d1c6f2e8f6a7546ba288952cd8b2f27532ed28ba0205aab0b2a0ce3b3fc4f63b08c1c325589d6faed23b315802a6cef82f68352a2116ff2755956258467a4b5aa8f157a6c683c8a4a9c1ac2b073eb8ea1b919e745de5d7d51a2f18c6e11bb6a2b5b9e3837cd0d5848a5db4aee7d2fdf7ab734833fbfe8c1470128fd5707b85710dddb4ebdc49eff82a74238c2e64a1e16585cb52a80c5fae6c3c592e3c9a06b0627b41b9bc7b6c514542c8ec5f85224798e39ea27f2c34c72ce925489eb8212f14e67fd788f49abfb950bd6d9c07ab3783ce86c9937dfa4fd333bd1f6e82478cfd5ad30773f4096b314e9bcfff8770052b2fe58547d03f6cd7848fe24f1efeeec17099b26058ac94fe54268472838da00da4154694380bdc8c6f9ee43103cdf0d93d54eb615e05a8ebeb9a95876b818e2f5522f8675cecead549dd13acaca314c9f01a556197bf93ece5b544a1ee136bc116412fd1ca51fe0874c2d8b4794e754cb8d73e8bfe7d21acab20b0707f2be54cd8f99bc568ccccfeebe3928810cc8840f62b3785f578a51f37f0756fe3ca43579e4d049ce9d5754e4e4ada908b0e063f3e52e24d1bee78f7cfab25b1bb867d562c93d53b0143ecc3b79924ea40087b687ede4d15a66c46d44a29002ecd9da6995f1d0b4e0a7be396f29e544b9a762b52d93e17818e396bd5192b9fae26f34dfdda3dbd7e666b0be11dce71cc083279b1e66d9913bd97c576143d3994a4374367380f8c8c784f62050622307000000000
```

### How to derive a 32-byte public key from a 612-byte signing key (<strong>pk.pub</strong>)

```console
$ cargo run --quiet -- --generate_sk | cargo run --quiet -- --derive_pk  ; echo
6da33c998de0f9dfc1aa32e197044f8b4482b2c9e74d162feeb3c32d57afb14b
```

### How to get period from a 612-byte signing key (<strong>period</strong>)
```console
$ cargo run --quiet -- --generate_sk | cargo run --quiet -- --get_period ; echo
0
```

### How to sign message using a 612-byte signing key (<strong>signature</strong>) and verify signature using the corresponding public key
```console
$ cat sk.prv
64c1ed65ee9f14820ab5b3085de2f51a3c852e790150faf3ce920622f2feee7bfdf988699351a952112f481ae2165768951d962f9e4093428ff27641d458986da3fb7209204bb538a0ba10bc1a261fb12ef589e7c540a52159c45989e13b38cb04082801c20c948daaf4de164e339247e0c006525117308f87a97c476eb292030d09cd9070e6e823fbc5db7c8d82c2d95bfed7f245161c82bdf21765eefeda9d2019836e6eda4f6a99d997d3658059f11e8ee7394b7ad77c3218f97fa91d24067c7f801e93222c1f261d9711ed08da8187ca4f113691da9855bb8749fa6e279d2c073334b2d4721d1f6af6423af7f6314e8d299f794164fd90008c09cf0e2a38a3affa465f0f60c3dc3f7f8c32c4675084d80977bd46e9caea6a007038cec96fe7ef67e4788080b2ad12a122d8dc0be1cd912f48d16e1a5acfeef105869a10025b226e15630709a0289bfd40988e1fcc6cf58edf85edcf77bb3dee8bbc0b870be13d8bde5d372787c4b32b2dd48ae593b1023568ac7e7806d743fa540976e6a5865e634120a3ad9023a67e2876f0bb60eb075080086d33bb5956dc76378356a7097e1dae50a40284e376b2b875d5693b99a00f93cebfc42a03afc09d5da98e17c7b185ce83818c9168bacc24ffa23baa27427aa06a4496b9c20d571dbcd0ed22f407399fcb4c53ccbc5f5218c808f5d9368df5c64d68eadafb6eab5d73f61bb8bca5e4ed2b08a31e57e48e24356e7775d027b9448284d6f1e22f03f220131b0344fcd86f604a59abe2bc187521f406a46324de49996715b26e39f2315b3be09da70649dee75e6578b5e516d74346b36892d84a0ce7c3d49aa8df63571c3eb8da00000000

$ cargo run --quiet -- --derive_pk sk.prv > pk.pub
$ cat pk.pub
c1e42412ef90b6659a1d8b09192adcea742173c8564ad2e2c1cadb5c837fbfa6

$ echo -n "msg" | cargo run --quiet -- --sign sk.prv > signature
$ cat signature
54b69e5854823ee69e4cdbb515e5a03c015ab89d0c7324bdc90563766253c40a352be171c2003b02aea33f6411588f923fadc236a2e998f8b0d04d8956ad7e0da3fb7209204bb538a0ba10bc1a261fb12ef589e7c540a52159c45989e13b38cb04082801c20c948daaf4de164e339247e0c006525117308f87a97c476eb292032019836e6eda4f6a99d997d3658059f11e8ee7394b7ad77c3218f97fa91d24067c7f801e93222c1f261d9711ed08da8187ca4f113691da9855bb8749fa6e279da3affa465f0f60c3dc3f7f8c32c4675084d80977bd46e9caea6a007038cec96fe7ef67e4788080b2ad12a122d8dc0be1cd912f48d16e1a5acfeef105869a1002e13d8bde5d372787c4b32b2dd48ae593b1023568ac7e7806d743fa540976e6a5865e634120a3ad9023a67e2876f0bb60eb075080086d33bb5956dc76378356a7c7b185ce83818c9168bacc24ffa23baa27427aa06a4496b9c20d571dbcd0ed22f407399fcb4c53ccbc5f5218c808f5d9368df5c64d68eadafb6eab5d73f61bb844fcd86f604a59abe2bc187521f406a46324de49996715b26e39f2315b3be09da70649dee75e6578b5e516d74346b36892d84a0ce7c3d49aa8df63571c3eb8da

$ echo -n "msg" | cargo run --quiet -- --verify $(cat signature) pk.pub
OK

$ echo "msg" | cargo run --quiet -- --verify $(cat signature) pk.pub
Fail
```

### How to sign message using a 612-byte signing key (<strong>signature</strong>) and verify signature using the corresponding public key

```console
$ cargo run --quiet -- --generate_sk > sk.prv
$ cat sk.prv
d6f263b227d8c36f0b459878972c4c432fe778f395c08b9cbc732f27280853533bc998541c9d322b7ffd11e66b445d65ed079992d3f7fd05cc4a6174c2c6c88cb6be55f612daa656cb4f23ff696bd96315f57e1a162cd9116203d4017196c683fb478a3b9683e13620294c5a2b4d9ea1a3f9314f59f691bacb724a5cec03cc6708b5ae50e4c5bb62df9a2bfdc6a917fc6a9e89c494fc608f31669c050f0c7b1d697726ce897f4b4895b6b5766f8d1569c416a8811f29dbf6d19cdf02a5d349221f25b8f7566aeba7eb2cf6a7f9921bd936b54ef5034465174634fd09c636b2c95707de46fc62fc49d1330c2ee8a7250c29a64ecd65b2e989be451faf4d2068281e061dc06395645076d4da91f407beadf69d8061ff09f8a4ec6712cc691f565f51c46b505161e63273a3ad44663ba1db4e18848350bda32ae9bcc0ab0bf6e6b8fe6853da90d476cec778ba02f38f51517a72125409ca943250e33a7cc6632ba0ec32fd4c77f8c1988328f6b2a7aa75635c5be3b272a12ffbcb19870aaf858ac7cf66df4c18afb1829840606dd2dc5ce0c73e8c10ecd9d58728a80bdc395c86b91abfee9e37c750481662bbaf677707ec5ddc56cdd16e67b51c5318da582a9bde1f1c1cb062213359e3ca16fe0d8844319bd7ffbd40873f795bbd72ca3f1066c816a4e0cd1dc57f88a0360ba192076548540a01fb308fcb69938ecd6d7bf7821dc421948d3f38037d78461fa47e4e20b3b39e446f342543d3a6c6476288b62628848c9d01bf342b08759d7fdd0b86ad8fea0379f2ec9d99d67bb3424b32031c365d5d7363576ea1972cdc5e07b0e20bdde530e729f2968ef41d9e56bd75ffcff900000000

$ cargo run --quiet -- --get_period sk.prv
0

$ cargo run --quiet -- --update_sk sk.prv > sk1.prv
3bc998541c9d322b7ffd11e66b445d65ed079992d3f7fd05cc4a6174c2c6c88c0000000000000000000000000000000000000000000000000000000000000000b6be55f612daa656cb4f23ff696bd96315f57e1a162cd9116203d4017196c683fb478a3b9683e13620294c5a2b4d9ea1a3f9314f59f691bacb724a5cec03cc6708b5ae50e4c5bb62df9a2bfdc6a917fc6a9e89c494fc608f31669c050f0c7b1d697726ce897f4b4895b6b5766f8d1569c416a8811f29dbf6d19cdf02a5d349221f25b8f7566aeba7eb2cf6a7f9921bd936b54ef5034465174634fd09c636b2c95707de46fc62fc49d1330c2ee8a7250c29a64ecd65b2e989be451faf4d2068281e061dc06395645076d4da91f407beadf69d8061ff09f8a4ec6712cc691f565f51c46b505161e63273a3ad44663ba1db4e18848350bda32ae9bcc0ab0bf6e6b8fe6853da90d476cec778ba02f38f51517a72125409ca943250e33a7cc6632ba0ec32fd4c77f8c1988328f6b2a7aa75635c5be3b272a12ffbcb19870aaf858ac7cf66df4c18afb1829840606dd2dc5ce0c73e8c10ecd9d58728a80bdc395c86b91abfee9e37c750481662bbaf677707ec5ddc56cdd16e67b51c5318da582a9bde1f1c1cb062213359e3ca16fe0d8844319bd7ffbd40873f795bbd72ca3f1066c816a4e0cd1dc57f88a0360ba192076548540a01fb308fcb69938ecd6d7bf7821dc421948d3f38037d78461fa47e4e20b3b39e446f342543d3a6c6476288b62628848c9d01bf342b08759d7fdd0b86ad8fea0379f2ec9d99d67bb3424b32031c365d5d7363576ea1972cdc5e07b0e20bdde530e729f2968ef41d9e56bd75ffcff900000001

$ cargo run --quiet -- --get_period sk1.prv
1
```
