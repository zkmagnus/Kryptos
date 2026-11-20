#!/usr/bin/env python3
"""Check public seed vectors independently of Rust and its dependencies.

All inputs below are public test material. This script has no wallet inputs and
must never be used to generate funded keys. See docs/seed-derivation-compatibility.md.
"""

import hashlib
import unicodedata


PHRASE = " ".join(["abandon"] * 23 + ["art"])
BIP39_TREZOR_SEED = (
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af"
    "7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
)
EMPTY_PASSPHRASE_SEED = (
    "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c"
    "6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
)
EXPECTED_KEYS = {
    "master": "939edc84b8082c372f6946ba2ba426a3643f557279559b3948b630c6c38d26b3",
    "purpose": "6c7f416029f7af9a825c7708d0104dbcba1bd90389672eb25fbfa12b82a6a48f",
    "coin_type": "998868c0baa59b676dde0d0dfbdb0d39663d3ec9a7ea51c96625fceef11d2f75",
    "account_0": "88cffd3a1ae06fdcc3096cfdd5d488961565de3fbc9d981117ba84edecd4863a",
    "account_1": "7736bcda73926421570caa1d2375dc2d71ddc33c32194be23d78f80658274f84",
}


def bip39_seed(passphrase):
    return hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", PHRASE).encode("utf-8"),
        ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8"),
        iterations=2048,
        dklen=64,
    )


def child(parent, index):
    if not 0 <= index < 2**31:
        raise ValueError("hardened child index must be below 2^31")
    sk, chain_code = parent[:32], parent[32:]
    data = chain_code + b"\x81" + sk + (index | 0x80000000).to_bytes(4, "little")
    return hashlib.blake2b(data, digest_size=64, person=b"ExpandSeed______").digest()


def check_equal(name, actual, expected):
    if actual.hex() != expected:
        raise SystemExit(f"public test vector mismatch at {name}")


def main():
    # Standard BIP39 vector, independent of Kryptos's empty-passphrase choice.
    check_equal("BIP39 TREZOR", bip39_seed("TREZOR"), BIP39_TREZOR_SEED)
    seed = bip39_seed("")
    check_equal("BIP39 empty passphrase", seed, EMPTY_PASSPHRASE_SEED)
    master = hashlib.blake2b(seed, digest_size=64, person=b"IP32Master______").digest()
    purpose = child(master, 32)
    coin_type = child(purpose, 1)
    nodes = {
        "master": master,
        "purpose": purpose,
        "coin_type": coin_type,
        "account_0": child(coin_type, 0),
        "account_1": child(coin_type, 1),
    }
    for name, node in nodes.items():
        check_equal(name, node[:32], EXPECTED_KEYS[name])
    print("Verified BIP39 references and five Kryptos derivation stages independently.")


if __name__ == "__main__":
    main()
