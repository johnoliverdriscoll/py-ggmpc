[![Build Status](https://app.travis-ci.com/johnoliverdriscoll/py-ggmpc.svg?branch=master)](https://app.travis-ci.com/johnoliverdriscoll/py-ggmpc)
[![Documentation Status](https://readthedocs.org/projects/py-ggmpc/badge/?version=latest)](https://py-ggmpc.readthedocs.io/en/latest/?badge=latest)

# ggmpc

This is an implementation of
[Gennaro-Goldfeder threshold signatures](https://eprint.iacr.org/2020/540.pdf).

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

Read the automatically generated [documentation](https://py-ggmpc.readthedocs.io/en/latest/?badge=latest) and [unit tests](https://github.com/johnoliverdriscoll/py-ggmpc/blob/master/test/test_library_methods.py).

## Command line

This project includes a command line utility that can perform all features.

```shell
usage: ggmpc [-h] COMMAND ...

positional arguments:
    COMMAND
      keyshare     create key shares
      keycombine   combine key shares
      signshare    create signing shares
      signconvert  convert signing shares
      signcombine  combine converted signing shares and signature shares
      sign         sign message using converted signing shares
      verify       verify a signature
      deserialize  deserialize data

optional arguments:
  -h, --help       show this help message and exit
```

Examples of complete end-to-end key generation and signing flows using the
command line utility can be found in the [TESTING](TESTING.md) document.
