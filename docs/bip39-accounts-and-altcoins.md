# Accounts and Derivation Paths
## Accounts Checked by Default
By default, seedrecover.py will check **the first account of each address type** using common derivation paths for BIP39 wallets. (BIP39 will default to Bitcoin if no coin is specified) You can select to have seedrecover check for altcoins if selected via the gui or specified via --wallet-type in the command line. 

To use the 2nd account, etc, you typically increment the last digit of the derivation path from /0 to /1.

** The currencies and derivation paths supported by default (These files can all be found in the /derivationpath-lists/ folder of the repository)**
### Bitcoin
**BIP39 (BTC.txt)**
``` linenums="1"
{% include "../derivationpath-lists/BTC.txt" %}
```

**Electrum (Electrum.txt)**
``` linenums="1"
{% include "../derivationpath-lists/Electrum.txt" %}
```


### Bitcoin Cash
**BCH.txt**
``` linenums="1"
{% include "../derivationpath-lists/BCH.txt" %}
```

### Cardano
Cardano handles this a bit differently as there are major differences between how different vendors implement Cardano account derivation.
As such, you will notice that derivation paths for Cardano have an additional prefix for the derivation type. 
By default, BTCRecover will check all three "Shelly" derivation types and this can have a major performance impact. As such, if you know which wallet the seed came from, you should disable the other unnecessary derivation paths.

**ADA.txt**
``` linenums="1"
{% include "../derivationpath-lists/ADA.txt" %}
```

### Dash
**Dash.txt**
``` linenums="1"
{% include "../derivationpath-lists/DASH.txt" %}
```


### DigiByte
**DGB.txt**
``` linenums="1"
{% include "../derivationpath-lists/DGB.txt" %}
```


### Ethereum
**ETH.txt**
``` linenums="1"
{% include "../derivationpath-lists/ETH.txt" %}
```


### Groestlcoin
**GRS.txt**
``` linenums="1"
{% include "../derivationpath-lists/GRS.txt" %}
```


### Litecoin
**LTC.txt**
``` linenums="1"
{% include "../derivationpath-lists/LTC.txt" %}
```


### Monacoin
**MONA.txt**
``` linenums="1"
{% include "../derivationpath-lists/MONA.txt" %}
```


### Ripple
**XRP.txt**
``` linenums="1"
{% include "../derivationpath-lists/XRP.txt" %}
```


### Vertcoin
**VTC.txt**
``` linenums="1"
{% include "../derivationpath-lists/VTC.txt" %}
```


### Zilliqa
**ZIL.txt**
``` linenums="1"
{% include "../derivationpath-lists/ZIL.txt" %}
```


## Custom Derivation Paths
You can also edit the files in the common-derivation-pathslists folder to either add, or remove derivation paths that will be searched, as removing those that aren't required will speed things up a bit... 

You can also use the --bip32-path argument to specify a derivation path (or paths) via the commandline.

## Altcoins, forks,clones or custom derivation paths
You can also try to specifiy a custom derivation path for altcoins/forks which share the same address format as any supported coins. (Though this doesn't necessarily mean the coin uses the same derivation function.)

## Adding Unsupported Coins

If you want the tool to support a crypto that isn't listed above, please test that it works and submit a PR which includes a unit test for that coin and also any required code to accept the address format.

**_If you are trying to do a recovery for a coin that isn't listed above, feel free to contact me as it may be possible for you to sponsor the addition of that crypto as part of an assisted recovery fee._**
