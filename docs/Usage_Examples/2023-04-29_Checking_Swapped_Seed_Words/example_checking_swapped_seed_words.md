# Grouping words together in tokenlist based seed recoveries

## Background
Sometimes someone has swapped words within their mnemonic in an attempt to add a layer of security to be back, but has since forgotten exactly which words they swapped.

seedrecover.py has the ability to check mnemonics in the situation where a number of words have been swapped within the mnemonic.

This is done using the `--transform-wordswaps` argument and specifying how many swaps you want to check for each generated seed.

## Standard Recovery Example
You can simply use the standard seedrecover.py commands in conjunction with this argument, in both situations where you have all the words correct as well as situations where you think there may be additional erros within the mnemonic.

In the case that you don't believe that there are any additional errors, you can also set `--typos 0`

For example, the command below can be used to recover a mnemonic where there were two pairs of words that have been swapped, but we believe that we have all the correct words as well as the first address from the wallet.
```
python seedrecover.py --mnemonic "harvest enrich pave before correct dish busy one bulk chat mean biology" --typos 0 --dsw --addr-limit 1 --addrs 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --wallet-type bip39 --transform-wordswaps 2
```

You will get the correct seed within a few seconds...
