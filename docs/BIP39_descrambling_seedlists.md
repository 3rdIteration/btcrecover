# Token Lists, Password Lists and BIP39 Seed Phrases

## Tokenlists
The same "token list" functionality that can be used for creating passwords can also be used for creating seed phrases.

This feature can be used to unscramble seed phrases where the words of the passphrase are available, but the ordering is unknown. (This is currently only really practical with a 12 word seed phrase, though is also usable for a 24 word seed where the position of 12 of the words is known)

The syntax for creating these files is identical and information about that can be found here: [The Tokenlist File](tokenlist_file.md)

An example of a file which has 6 characters of of known position and 6 unknown can be found here: [Sample TokenList](https://github.com/3rdIteration/btcrecover/blob/master/btcrecover/test/test-listfiles/SeedTokenListTest.txt)

An example command that will use this tokenlist is:
`python3 seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --tokenlist ./btcrecover/test/test-listfiles/SeedTokenListTest.txt`

**It should be noted that you will need to specify the mnemonic length and the language when using this method** [Supported languages can be found here](https://github.com/3rdIteration/btcrecover/tree/master/btcrecover/wordlists)

BTCRecover can also print the seeds that will be tested via the `--listpass` command, something that can be useful for debugging your tokenlist [See here for more info about seedlists](passwordlist_file.md) from a tokenlist... (Also useful if you will be generating lots of seed phrases, though this currently just dumps out text files that will get very large, very quickly... Will optimise this a bit in the future)

## Seedlists
The "passwordlist" (See [here](passwordlist_file.md)) functionality can also be used with seedphrases through the `--seedlist` argument.

The key difference from the password list is that while you still simply list one seed phrase per line, you will also need to format them in the same style that are exported via the `--listpass` command. This is to make it possible for the output of the tokenlst step of this tool to be directly used by the passwordlist step. See [Sample Seedlist](https://github.com/3rdIteration/btcrecover/blob/master/btcrecover/test/test-listfiles/SeedListTest.txt)

Example Usage for SeedList (Seedlist created using listseeds as the output from the token list command above):
`python3 seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --seedlist ./btcrecover/test/test-listfiles/SeedListTest.txt`
