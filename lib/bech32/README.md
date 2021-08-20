bech32 [![travis-ci build status](https://api.travis-ci.com/fiatjaf/bech32.svg?branch=master)](https://travis-ci.com/fiatjaf/bech32)
======

Since this implementation wasn't in a place that was easy to use for Python programmers I took it from from https://github.com/rustyrussell/lightning-payencode and published [on GitHub](https://github.com/fiatjaf/bech32) and [on PyPI](https://pypi.org/project/bech32/).

The original version of this package is probably the one at https://github.com/sipa/bech32/tree/master/ref/python, but apparently Rusty Russel commented out the 90-length limit of bech32-encoded stuff so it could be used for Lightning invoices. Let's keep that change.

Install
-------

```
pip install bech32
```
