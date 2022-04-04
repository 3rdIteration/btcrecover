# Grouping words together in tokenlist based seed recoveries

## Background
Sometimes there are recoveries where someone may have either written their seed in such a way that they are unsure of the order, or split the backup in to multiple parts. Either way, this can mean that are words grouped together in such a way that their relative ordering is known, but the position of these words within the larger seed is not.

In situations like this, you can use a single comma character `,` (No space, just a single comma) for words within a tokenlist to indicate that words must be used together, in the provided order. This is similar to the "relative anchor" feature, but is both far more efficient and also allows for multiple word groupings. 

Grouped word tokens can also be used in conjunction with other types of anchors, positional, etc. 

Using these tokens also means that the number of tokens will no longer equal the mnemonic length (as it typically does for descrambling with single word tokens) so you can also make use of the `--min-tokens` and `--max-tokens` arguments to specify the minimum number of tokens that should be tried for any given seed guess. (A comma separated group of words counts as a single token)

Like with seed descrambling, the ceiliing for this sort of recovery is based off the number of tokens, generally (without positional anchors) there will be max-tokens! (max-tokens factorial) possible seeds to check.

## Example

The following example uses the following tokenlist:
``` linenums="1"
{% include "tokengroups_tokenlist.txt" %}
```

You can see in this tokenlist that there are a few blocks of tokens that we are sure are in the correct order, (Including a positional anchor for one of the groups of seed words) as well as a few extra/single words. 

And is run with the following command (Will find a result in a few seconds)
```
python seedrecover.py --tokenlist ./docs/Usage_Examples/2022-04-02_Seed_Tokenlist_TokenBlocks/tokengroups_tokenlist.txt --mnemonic-length 24 --language en --wallet-type bip39 --addrs 1PTcESpqrmWePYB5h18Ni11QTKNfMkdSYJ --dsw --addr-limit 10 --max-tokens 9 --min-tokens 8
```

The correct seed is:
`basic dawn renew punch arch situate resist indicate call lens group empty brother damp this verify eternal injury arrest question armor hole lounge practice`

And as you can see, this is made up of some of the token-groups included in the tokenlist file above.