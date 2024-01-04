Script types
============

This is an overview script types used in transaction Input and Outputs.

They are defined in main.py


Locking scripts
---------------

Scripts lock funds in transaction outputs (UTXO's).
Also called ScriptSig.


+-------------+---------------------------+-----------+-------------------+------------+
| Lock Script | Script to Unlock          | Encoding  | Key type / Script | Prefix BTC |
+=============+===========================+===========+===================+============+
| p2pkh       | Pay to Public Key Hash    | base58    | Public key hash   | 1          |
+-------------+---------------------------+-----------+-------------------+------------+
| p2sh        | Pay to Script Hash        | base58    | Redeemscript hash | 3          |
+-------------+---------------------------+-----------+-------------------+------------+
| p2wpkh      | Pay to Wallet Pub Key Hash| bech32    | Public key hash   | bc         |
+-------------+---------------------------+-----------+-------------------+------------+
| p2wsh       | Pay to Wallet Script Hash | bech32    | Redeemscript hash | bc         |
+-------------+---------------------------+-----------+-------------------+------------+
| multisig    | Multisig Script           | base58    | Multisig script   | 3          |
+-------------+---------------------------+-----------+-------------------+------------+
| pubkey      | Public Key (obsolete)     | base58    | Public Key        | 1          |
+-------------+---------------------------+-----------+-------------------+------------+
| nulldata    | Nulldata                  | n/a       | OP_RETURN script  | n/a        |
+-------------+---------------------------+-----------+-------------------+------------+


Unlocking scripts
-----------------

Scripts used in transaction inputs to unlock funds from previous outputs.
Also called ScriptPubKey.

+---------------+---------------------------+----------------+-------------------------+
| Locking sc.   | Name                      | Unlocks        | Key type / Script       |
+===============+===========================+================+=========================+
| sig_pubkey    | Signature, Public Key     | p2pkh          | Sign. + Public key      |
+---------------+---------------------------+----------------+-------------------------+
| p2sh_multisig | Pay to Script Hash        | p2sh, multisig | Multisig + Redeemscript |
+---------------+---------------------------+----------------+-------------------------+
| p2sh_p2wpkh   | Pay to Wallet Pub Key Hash| p2wpkh         | PK Hash + Redeemscript  |
+---------------+---------------------------+----------------+-------------------------+
| p2sh_p2wsh    | Multisig script           | p2wsh          | Redeemscript            |
+---------------+---------------------------+----------------+-------------------------+
| signature     | Sig for public key (old)  | pubkey         | Signature               |
+---------------+---------------------------+----------------+-------------------------+


Bitcoinlib script support
-------------------------

The 'pubkey' lockscript and 'signature' unlocking script are ancient and not supported by BitcoinLib at
the moment.

Using different encodings for addresses then the one listed in the Locking Script table is possible but
not adviced: It is not standard and not sufficiently tested.
