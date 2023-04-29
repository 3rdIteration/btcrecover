# Grouping words together in tokenlist based seed recoveries

## Background
Sometimes someone has swapped words within their mnemonic in an attempt to add a layer of security to their seed backup, but has since forgotten exactly which words they swapped.

seedrecover.py has the ability to check mnemonics in the situation where a number of words have been swapped within the mnemonic.

This is done using the `--transform-wordswaps` argument and specifying how many swaps you want to check for each generated seed.

In terms of working out the practical limits to this type of recovery, for a given number of swaps N in a mnemonic of length L, there will generally be (L/2 * (L-1))^N additional possible seeds. (Not accounting for skipped duplicates, etc)

You can see what this works out to for 12 and 24 word seeds when swapping up to three words below.

| Mnemonic Length | Possibilities with 1 Swap | Possibilities with 2 Swaps | Possibilities with 3 Swaps |
|---|---|---|---|
| 12              |	67 |	4423 |	291919 |
| 24              |	277 |	76453 |	21101029 |

As you can see, recoveries for up to four swaps are quite straightforward and the complexity grows exponentially beyond this.

## Standard Recovery Example
You can simply use the standard seedrecover.py commands in conjunction with this argument, in both situations where you have all the words correct as well as situations where you think there may be additional erros within the mnemonic.

In the case that you don't believe that there are any additional errors, you can also set `--typos 0`

For example, the command below can be used to recover a mnemonic where there were two pairs of words that have been swapped, but we believe that we have all the correct words as well as the first address from the wallet.
```
python seedrecover.py --mnemonic "harvest enrich pave before correct dish busy one bulk chat mean biology" --typos 0 --dsw --addr-limit 1 --addrs 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --wallet-type bip39 --transform-wordswaps 2
```

You will get the correct seed within a few seconds...

Correct Seed: harvest bulk pave before enrich dish busy one correct chat mean biology

## Seedlist Recovery Example
You can also use this feature when using seedrecover.py with either a seedlist or tokenlist.

Let's say that you had a number of seeds where you knew that you have swapped pairs of words up to three times, have forgotten which were swapped and also forgotten which seed is associated with the wallet you are trying to find.

You might create a seedlist like the one below:

The following example uses the following seedlist:
``` linenums="1"
{% include "seed_swaps_example_seedlist.txt" %}
```

You would then run seedrecover using this seedlist using the command below:
```
python seedrecover.py --seedlist ./docs/Usage_Examples/2023-04-29_Checking_Swapped_Seed_Words/seed_swaps_example_seedlist.txt --dsw --addr-limit 1 --addrs 175s5ftTjfoPzyNLM2CnNLBFeE1zXHuApU --wallet-type bip39 --transform-wordswaps 3 --mnemonic-length 12 --language en
```

You will get the correct result within about a minute.

Correct Seed: oil debate panther dismiss width flame grocery style vault belt brisk food