Caching
=======

Results from queries to service providers are store in a cache database. Once transactions are confirmed and stored
on the blockchain they are immutable, so they can be stored in a local cache for an indefinite time.

What is cached?
---------------

The cache stores transactions, but also address information and transactions-address relations. This speeds up
the gettransactions(), getutxos() and getbalance() method since all old transactions can be read from cache, and we
only have to check if new transactions are available for a certain address.

The latest block - block number of the last block on the network - is stored in cache for 60 seconds. So the Service
object only checks for a new block every minute.

The fee estimation for a specific network is stored for 10 minutes.


Using other databases
---------------------

By default the cache is stored in a SQLite database in the database folder: ~/.bitcoinlib/databases/bitcoinlib_cache.sqlite
The location and type of database can be changed in the config.ini with the default_databasefile_cache variable.

Other type of databases can be used as well, check
http://bitcoinlib.readthedocs.io/en/latest/_static/manuals.databases.html for more information.


Disable caching
---------------

Caching is enabled by default. To disable caching set the environment variable SERVICE_CACHING_ENABLED to False or
set this variable (service_caching_enabled) in the config.ini file placed in your .bitcoinlib/config directory.


Troubleshooting
---------------

Nothing is cached, what is the problem?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- If the min_providers parameter is set to 2 or more caching will be disabled.
- If a service providers returns an incomplete result no cache will be stored.
- If the after_txid parameter is used in gettransactions() or getutxos() no cache will be stored if this
  the 'after_txid' transaction is not found in the cache. Because the transaction cache has to start from the first
  transaction for a certain address and no gaps can occur.

I get incomplete or incorrect results!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Please post an issues in the Github issue-tracker so we can take a look.
- You can delete the database in ~/.bitcoinlib/databases/bitcoinlib_cache.sqlite for an easy fix, or disable caching
  if that really doesn't work out.