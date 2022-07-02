# BlockIo

This Python package is the official reference client for the Block.io payments API. To use this, you will need the Dogecoin, Bitcoin, or Litecoin API key(s) from <a href="https://block.io" target="_blank">Block.io</a>. Go ahead, sign up :)

#### COMPATIBILITY: Please use Python 3.7, 3.8, 3.9, 3.10. Untested on Windows: ensure all tests pass before using this package regardless.

## Installation

[Using virtualenv is recommended when installing Python packages](https://packaging.python.org/en/latest/installing.html#virtual-environments).

Install the package using `pip3`:

    pip3 install block-io

## Usage

It's super easy to get started. In your Python shell, do:

    from block_io import BlockIo

    block_io = BlockIo('API KEY', 'SECRET PIN', API_VERSION)

    # print the account balance
    print block_io.get_balance()

    # print all addresses on this account
    print block_io.get_my_addresses()

For more information, see [Python API Docs](https://block.io/api/simple/python). This Python client provides a mapping for all methods listed on the Block.io API site.

## Contributing

1. Fork it ( https://github.com/BlockIo/block_io-python/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
