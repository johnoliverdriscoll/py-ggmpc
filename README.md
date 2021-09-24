[![Build Status](https://app.travis-ci.com/johnoliverdriscoll/py-ggmpc.svg?branch=master)](https://app.travis-ci.com/johnoliverdriscoll/py-ggmpc)
[![Documentation Status](https://readthedocs.org/projects/py-ggmpc/badge/?version=latest)](https://py-ggmpc.readthedocs.io/en/latest/?badge=latest)

# ggmpc

This is an implementation of MPC threshold signatures for both ECDSA and EdDSA.
The ECDSA implementation is based on [Fast Multiparty Threshold ECDSA with Fast
Trustless Setup](https://eprint.iacr.org/2020/540.pdf). The EdDSA implementation is based on [Provably Secure Distributed Schnorr Signatures and a (*t*, *n*)
Threshold Scheme for Implicit Certificates](https://github.com/ZenGo-X/multi-party-schnorr/blob/master/papers/provably_secure_distributed_schnorr_signatures_and_a_threshold_scheme.pdf).

# Installation

## PIP

```shell
$ pip3 install ggmpc
```

## Building from source

```shell
$ sudo apt-get install git
$ git clone https://github.com/johnoliverdriscoll/py-ggmpc
$ cd py-ggmpc
$ pip3 install .
$ python3 -m unittest -v
```

# Usage

## Python package

Read the automatically generated [documentation](https://py-ggmpc.readthedocs.io/en/latest/?badge=latest) and [unit tests](https://github.com/johnoliverdriscoll/py-ggmpc/blob/master/test).

## Command line

This project includes a command line utility that can perform all features.
Examples of complete end-to-end key generation and signing flows using the
command line utility can be found in the [TESTING](TESTING.md) document.
