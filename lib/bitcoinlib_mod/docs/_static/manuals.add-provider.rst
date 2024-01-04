Add a new Service Provider
==========================

The Service class connects to providers such as Blockchain.info or Blockchair.com to retreive transaction,
network, block, address information, etc

The Service class automatically selects a provider which has requested method available and selects another
provider if method fails.


Steps to add a new provider
---------------------------

* The preferred way is to create a github clone and update code there (and do a pull request...)
* Add the provider settings in the providers.json file in the configuration directory.

Example:

.. code-block:: json

    {
        "bitgo": {
            "provider": "bitgo",
            "network": "bitcoin",
            "client_class": "BitGo",
            "provider_coin_id": "",
            "url": "https://www.bitgo.com/api/v1/",
            "api_key": "",
            "priority": 10,
            "denominator": 1,
            "network_overrides": null
        }
    }

* Create a new Service class in bitcoinlib.services. Create a method for available API calls and rewrite output
  if needed.

Example:

.. code-block:: python

    from bitcoinlib.services.baseclient import BaseClient

    PROVIDERNAME = 'bitgo'


    class BitGoClient(BaseClient):

        def __init__(self, network, base_url, denominator, api_key=''):
            super(self.__class__, self).\
                __init__(network, PROVIDERNAME, base_url, denominator, api_key)

        def compose_request(self, category, data, cmd='', variables=None, method='get'):
            if data:
                data = '/' + data
            url_path = category + data
            if cmd:
                url_path += '/' + cmd
            return self.request(url_path, variables, method=method)

        def estimatefee(self, blocks):
            res = self.compose_request('tx', 'fee', variables={'numBlocks': blocks})
            return res['feePerKb']

* Add this service class to __init__.py

.. code-block:: python

    import bitcoinlib.services.bitgo

* Remove install.log file in bitcoinlib's log directory, this will copy all provider settings next time you run
  the bitcoin library. See 'initialize_lib' method in main.py
* Specify new provider and create service class object to test your new class and it's method

.. code-block:: python

    from bitcoinlib import services

    srv = Service(providers=['blockchair'])
    print(srv.estimatefee(5))

