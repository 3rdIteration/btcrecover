Install, Update and Tweak BitcoinLib
====================================

Installation
------------

Install with pip
~~~~~~~~~~~~~~~~

.. code-block:: none

    $ pip install bitcoinlib

Package can be found at https://pypi.org/project/bitcoinlib/

Install from source
~~~~~~~~~~~~~~~~~~~

Required packages:

``sudo apt install -y postgresql postgresql-contrib mysql-server libpq-dev libmysqlclient-dev``

Create a virtual environment for instance on linux with virtualenv:

.. code-block:: bash

    $ virtualenv -p python3 venv/bitcoinlib
    $ source venv/bitcoinlib/bin/activate

Then clone the repository and install dependencies:

.. code-block:: bash

    $ git clone https://github.com/1200wd/bitcoinlib.git
    $ cd bitcoinlib
    $ pip install -r requirements-dev.txt



Package dependencies
~~~~~~~~~~~~~~~~~~~~

Required Python Packages, are automatically installed upon installing bitcoinlib:

* fastecdsa
* pyaes
* scrypt (or much slower pyscript)
* sqlalchemy
* requests
* enum34 (for older Python installations)
* pathlib2 (for Python 2)
* six


Other requirements Linux
~~~~~~~~~~~~~~~~~~~~~~~~


``sudo apt install build-essential python-dev python3-dev libgmp3-dev``

To install OpenSSL development package on Debian, Ubuntu or their derivatives

``sudo apt install libssl-dev``

To install OpenSSL development package on Fedora, CentOS or RHEL

``sudo yum install gcc openssl-devel``


Development environment
~~~~~~~~~~~~~~~~~~~~~~~

Install database packages for MySQL and PostgreSQL

``sudo apt install mysql-server postgresql postgresql-contrib libmysqlclient-dev postgresql-server-dev-11``

From library root directory install the Python requirements

``pip install -r requirements-dev.txt``

Then run the unittests to see if everything works

``python setup.py test``



Other requirements Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~

This library requires a Microsoft Visual C++ Compiler. For python version 3.5+ you will need Visual C++ 14.0.
Install Microsoft Visual Studio and include the "Microsoft Visual C++ Build Tools" which can be downloaded from
https://visualstudio.microsoft.com/downloads. Also see https://wiki.python.org/moin/WindowsCompilers

The fastecdsa library is not enabled at this moment in the windows install, the slower ecdsa library is installed.
Installation of fastecdsa on Windows is possible but not easy, read https://github.com/AntonKueltz/fastecdsa/issues/11
for step you could take to install this library.

If you have problems with installing this library on Windows you could try to use the pyscrypt library instead of
scrypt. The pyscrypt library is pure Python so it doesn't need any C compilers installed. But this will run slower.


Update Bitcoinlib
-----------------

Before you update make sure to backup your database! Also backup your settings files in ./bitcoinlib/config if you
have made any changes.

If you installed the library with pip upgrade with

.. code-block:: none

    $ pip install bitcoinlib --upgrade

Otherwise pull the git repository.

After an update it might be necessary to update the config files. The config files will be overwritten
with new versions if you delete the .bitcoinlib/logs/install.log file.

.. code-block:: none

    $ rm .bitcoinlib/logs/install.log

If the new release contains database updates you have to migrate the database with the updatedb.py command.
This program extracts keys and some wallet information from the old database and then creates a new database.
The updatedb.py command is just a helper tool and not guaranteed to work, it might fail if there are a lot
of database changes. So backup database / private keys first and use at your own risk!

.. code-block:: none

    $ python updatedb.py
    Wallet and Key data will be copied to new database. Transaction data will NOT be copied
    Updating database file: /home/guest/.bitcoinlib/database/bitcoinlib.sqlite
    Old database will be backed up to /home/guest/.bitcoinlib/database/bitcoinlib.sqlite.backup-20180711-01:46
    Type 'y' or 'Y' to continue or any other key to cancel: y


Troubleshooting
---------------

When you experience issues with the scrypt package when installing you can try to solve this by installing
scrypt seperately:

.. code-block:: bash

    $ pip uninstall scrypt
    $ pip install scrypt

Please make sure you also have the Python development and SSL development packages installed, see 'Other requirements'
above.

You can also use pyscrypt instead of scrypt. Pyscrypt is a pure Python scrypt password-based key derivation library.
It works but it is slow when using BIP38 password protected keys.

.. code-block:: none

    $ pip install pyscrypt

If you run into issues do not hesitate to contact us or file an issue at https://github.com/1200wd/bitcoinlib/issues


Using library in other software
-------------------------------

If you use the library in other software and want to change file locations and other settings you can specify a
location for a config file in the BCL_CONFIG_FILE:

.. code-block:: python

    os.environ['BCL_CONFIG_FILE'] = '/var/www/blocksmurfer/bitcoinlib.ini'


Tweak BitcoinLib
----------------

You can `Add another service Provider <manuals.add-provider.html>`_ to this library by updating settings
and write a new service provider class.

If you use this library in a production environment it is advised to run your own Bcoin, Bitcoin, Litecoin or Dash node,
both for privacy and reliability reasons. More setup information:
`Setup connection to bitcoin node <manuals.setup-bitcoind-connection.html>`_

Some service providers require an API key to function or allow additional requests.
You can add this key to the provider settings file in .bitcoinlib/config/providers.json
