# Descrambling 12 Word Seeds
[YouTube Video can be found here: https://youtu.be/ruSF8OKwBRk](https://youtu.be/ruSF8OKwBRk)

Three types of token files are provided for these tests. Token files that will find the result on their first check, token files that will find the result as the last possible combination and those which will find it at some point inbetween.

The idea is that these allow you to quickly verify that things are working (finding on the first result), get an idea for how long a full run might take (last result) and also try something representative of a real world situation. 

If you are just descrambing a 12 word seed, there isn't much point running without --no-eta, as the number of seeds to be tested can be easily worked out and the seed generator can easily keep up with at least 48 threads.

**Note:** The YouTube video and examples were made before OpenCL acceleration was added to Blockchain.com wallets and can give a 2x performance improvement. (See [GPU Accleration](../../GPU_Acceleration.md) for more info) 

**Performance**

On a 48 core Linode you can expect to...
* Descramble a 12 word Electrum seed in less than 15 minutes…
* Descramble a 12 word BIP39 seed in less than 50 minutes…

_You can expect things to take about 5 times this long on a current (mid 2020), mid-range CPU._

## Electrum
### Legacy Wallet (Last Result)
**Using Tokenlist lastcombination_electrum.txt**
``` linenums="1"
{% include "./lastcombination_electrum.txt" %}
```

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --addr-limit 1 --addrs 1CU62HPowYSxhHiiNu1ukSbMjrkGj4x52i --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/lastcombination_electrum.txt --wallet-type electrum2
```

### Segwit Wallet
**Using Tokenlist randomcombination_electrum.txt**
``` linenums="1"
{% include "./randomcombination_electrum.txt" %}
```

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type electrum2 --addr-limit 1 --addrs bc1qtylwmarke39nysxepdx5xzfatvrlel5z8m0jx2 --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/randomcombination_electrum.txt --bip32-path "m/0'/0"
```

## BIP39
### Ethereum Address (Default derivation path for Trezor, MEW)
**Using Tokenlist randomcombination_bip39.txt**
``` linenums="1"
{% include "./randomcombination_bip39.txt" %}
```

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type ethereum --addr-limit 1 --addrs 0x66F9C09118B1C726BC24811a611baf60af42070A --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/randomcombination_bip39.txt --bip32-path "m/44'/60'/0'/0"
```

### Legacy BTC Address (First Result)
**Using Tokenlist firstcombination_bip39.txt**
``` linenums="1"
{% include "./firstcombination_bip39.txt" %}
```

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/firstcombination_bip39.txt
```

### Legacy BTC Address (Last Result)
**Using Tokenlist lastcombination_bip39.txt**
``` linenums="1"
{% include "./lastcombination_bip39.txt" %}
```
**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/lastcombination_bip39.txt
```

### Litecoin Native Segwit Address (Seed with Positional Anchors for known words, last word as any valid BIP39 word starting with 'B')
**Using Tokenlist fixedwords_bip39.txt**
``` linenums="1"
{% include "./fixedwords_bip39.txt" %}
```

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs ltc1q9srpp39hev6dpsxjjp8t5g0m3z7509vc9llalv --tokenlist ./docs/Usage_Examples/2020-05-02_Descrambling_a_12_word_seed/fixedwords_bip39.txt --bip32-path "m/84'/2'/0'/0"
```
