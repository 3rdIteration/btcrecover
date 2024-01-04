How to connect bitcoinlib to a bitcoin node
===========================================

This manual explains how to connect to a bitcoind server on your localhost or an a remote server.

Running your own bitcoin node allows you to create a large number of requests, faster response times,
and more control, privacy and independence. However you need to install and maintain it and it used
a lot of resources.


Bitcoin node settings
---------------------

This manual assumes you have a full bitcoin node up and running.
For more information on how to install a full node read https://bitcoin.org/en/full-node

Please make sure you have server and txindex option set to 1.

So your bitcoin.conf file for testnet should look something like this. For mainnet use port 8332,
and remove the 'testnet=1' line.

.. code-block:: text

    [rpc]
    rpcuser=bitcoinrpc
    rpcpassword=some_long_secure_password
    server=1
    port=18332
    txindex=1
    testnet=1


Connect using config files
--------------------------

Bitcoinlib looks for bitcoind config files on localhost. So if you running a full bitcoin node from
your local PC as the same user everything should work out of the box.

Config files are read from the following files in this order:
* [USER_HOME_DIR]/.bitcoinlib/config/bitcoin.conf
* [USER_HOME_DIR]/.bitcoin/bitcoin.conf

If your config files are at another location, you can specify this when you create a BitcoindClient
instance.

.. code-block:: python

    from bitcoinlib.services.bitcoind import BitcoindClient

    bdc = BitcoindClient.from_config('/usr/local/src/.bitcoinlib/config/bitcoin.conf')
    txid = 'e0cee8955f516d5ed333d081a4e2f55b999debfff91a49e8123d20f7ed647ac5'
    rt = bdc.getrawtransaction(txid)
    print("Raw: %s" % rt)


Connect using provider settings
-------------------------------

Connection settings can also be added to the service provider settings file in
.bitcoinlib/config/providers.json

Example:

.. code-block:: json

  {
    "bitcoind.testnet": {
      "provider": "bitcoind",
      "network": "testnet",
      "client_class": "BitcoindClient",
      "url": "http://user:password@server_url:18332",
      "api_key": "",
      "priority": 11,
      "denominator": 100000000
    }
  }


Connect using base_url argument
-------------------------------

Another options is to pass the 'base_url' argument to the BitcoindClient object directly.

This provides more flexibility but also the responsibility to store user and password information in a secure way.

.. code-block:: python

    from bitcoinlib.services.bitcoind import BitcoindClient

    base_url = 'http://user:password@server_url:18332'
    bdc = BitcoindClient(base_url=base_url)
    txid = 'e0cee8955f516d5ed333d081a4e2f55b999debfff91a49e8123d20f7ed647ac5'
    rt = bdc.getrawtransaction(txid)
    print("Raw: %s" % rt)


Please note: Using a remote bitcoind server
-------------------------------------------

Using RPC over a public network is unsafe, so since bitcoind version 0.18 remote RPC for all network interfaces
is disabled. The rpcallowip option cannot be used to listen on all network interfaces and rpcbind has to be used to
define specific IP addresses to listen on. See https://bitcoin.org/en/release/v0.18.0#configuration-option-changes

You could setup a openvpn or ssh tunnel to connect to a remote server to avoid this issues.
