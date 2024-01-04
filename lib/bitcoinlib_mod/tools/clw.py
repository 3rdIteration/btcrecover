# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#
#    CLW - Command Line Wallet manager.
#    Create and manage BitcoinLib legacy/segwit single and multisignatures wallets from the commandline
#
#    © 2019 November - 1200 Web Development <http://1200wd.com/>
#

import sys
import argparse
import binascii
import struct
import ast
from pprint import pprint
from bitcoinlib.wallets import HDWallet, wallets_list, wallet_exists, wallet_delete, WalletError, wallet_empty
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import to_hexstring
from bitcoinlib.main import BITCOINLIB_VERSION

try:
    import pyqrcode
    QRCODES_AVAILABLE = True
except ImportError:
    QRCODES_AVAILABLE = False

try:
    input = raw_input
except NameError:
    pass

DEFAULT_NETWORK = 'bitcoin'


def parse_args():
    parser = argparse.ArgumentParser(description='BitcoinLib command line wallet')
    parser.add_argument('wallet_name', nargs='?', default='',
                        help="Name of wallet to create or open. Used to store your all your wallet keys "
                             "and will be printed on each paper wallet")

    group_wallet = parser.add_argument_group("Wallet Actions")
    group_wallet.add_argument('--wallet-remove', action='store_true',
                              help="Name or ID of wallet to remove, all keys and transactions will be deleted")
    group_wallet.add_argument('--list-wallets', '-l', action='store_true',
                              help="List all known wallets in BitcoinLib database")
    group_wallet.add_argument('--wallet-info', '-w', action='store_true',
                              help="Show wallet information")
    group_wallet.add_argument('--update-utxos', '-x', action='store_true',
                              help="Update unspent transaction outputs (UTXO's) for this wallet")
    group_wallet.add_argument('--update-transactions', '-u', action='store_true',
                              help="Update all transactions and UTXO's for this wallet")
    group_wallet.add_argument('--wallet-recreate', '-z', action='store_true',
                              help="Delete all keys and transactions and recreate wallet, except for the masterkey(s)."
                                   " Use when updating fails or other errors occur. Please backup your database and "
                                   "masterkeys first.")
    group_wallet.add_argument('--receive', '-r', nargs='?', type=int,
                              help="Show unused address to receive funds. Specify cosigner-id to generate address for "
                                   "specific cosigner. Default is -1 for own wallet",
                              const=-1, metavar='COSIGNER_ID')
    group_wallet.add_argument('--generate-key', '-g', action='store_true', help="Generate a new masterkey, and show"
                              " passphrase, WIF and public account key. Can be used to create a multisig wallet")
    group_wallet.add_argument('--export-private', '-e', action='store_true',
                              help="Export private key for this wallet and exit")
    group_wallet.add_argument('--import-private', '-k',
                              help="Import private key in this wallet")

    group_wallet2 = parser.add_argument_group("Wallet Setup")
    group_wallet2.add_argument('--passphrase', nargs="*", default=None,
                               help="Passphrase to recover or create a wallet. Usually 12 or 24 words")
    group_wallet2.add_argument('--passphrase-strength', type=int, default=128,
                               help="Number of bits for passphrase key. Default is 128, lower is not adviced but can "
                                    "be used for testing. Set to 256 bits for more future proof passphrases")
    group_wallet2.add_argument('--network', '-n',
                               help="Specify 'bitcoin', 'litecoin', 'testnet' or other supported network")
    group_wallet2.add_argument('--database', '-d',
                               help="URI of the database to use",)
    group_wallet2.add_argument('--create-from-key', '-c', metavar='KEY',
                               help="Create a new wallet from specified key")
    group_wallet2.add_argument('--create-multisig', '-m', nargs='*',
                               metavar='.',
                               help='[NUMBER_OF_SIGNATURES, NUMBER_OF_SIGNATURES_REQUIRED, [KEY1, KEY2, ... KEY3]]'
                                    'Specificy number of signatures followed by the number of signatures required and '
                                    'then a list of public or private keys for this wallet. Private keys will be '
                                    'created if not provided in key list.'
                                    '\nExample, create a 2-of-2 multisig wallet and provide 1 key and create another '
                                    'key: -m 2 2 tprv8ZgxMBicQKsPd1Q44tfDiZC98iYouKRC2CzjT3HGt1yYw2zuX2awTotzGAZQ'
                                    'EAU9bi2M5MCj8iedP9MREPjUgpDEBwBgGi2C8eK5zNYeiX8 tprv8ZgxMBicQKsPeUbMS6kswJc11zgV'
                                    'EXUnUZuGo3bF6bBrAg1ieFfUdPc9UHqbD5HcXizThrcKike1c4z6xHrz6MWGwy8L6YKVbgJMeQHdWDp')
    group_wallet2.add_argument('--witness-type', '-y', metavar='WITNESS_TYPE', default=None,
                               help='Witness type of wallet: lecacy (default), p2sh-segwit or segwit')
    group_wallet2.add_argument('--cosigner-id', '-s', type=int, default=0,
                               help='Set this if wallet contains only public keys, more then one private key or if '
                                    'you would like to create keys for other cosigners.')
    group_transaction = parser.add_argument_group("Transactions")
    group_transaction.add_argument('--create-transaction', '-t', metavar=('ADDRESS_1', 'AMOUNT_1'),
                                   help="Create transaction. Specify address followed by amount. Repeat for multiple "
                                   "outputs", nargs='*')
    group_transaction.add_argument('--sweep', metavar="ADDRESS",
                                   help="Sweep wallet, transfer all funds to specified address")
    group_transaction.add_argument('--fee', '-f', type=int, help="Transaction fee")
    group_transaction.add_argument('--fee-per-kb', type=int,
                                   help="Transaction fee in sathosis (or smallest denominator) per kilobyte")
    group_transaction.add_argument('--push', '-p', action='store_true', help="Push created transaction to the network")
    group_transaction.add_argument('--import-tx', '-i', metavar="TRANSACTION",
                                   help="Import raw transaction hash or transaction dictionary in wallet and sign "
                                        "it with available key(s)")
    group_transaction.add_argument('--import-tx-file', '-a', metavar="FILENAME_TRANSACTION",
                                   help="Import transaction dictionary or raw transaction string from specified "
                                        "filename and sign it with available key(s)")

    pa = parser.parse_args()
    if pa.receive and pa.create_transaction:
        parser.error("Please select receive or create transaction option not both")
    if pa.wallet_name:
        pa.wallet_info = True
    else:
        pa.list_wallets = True
    return pa


def get_passphrase(args):
    inp_passphrase = Mnemonic('english').generate(args.passphrase_strength)
    print("\nYour mnemonic private key sentence is: %s" % inp_passphrase)
    print("\nPlease write down on paper and backup. With this key you can restore your wallet and all keys")
    passphrase = inp_passphrase.split(' ')
    inp = input("\nType 'yes' if you understood and wrote down your key: ")
    if inp not in ['yes', 'Yes', 'YES']:
        clw_exit("Exiting...")
    return passphrase


def create_wallet(wallet_name, args, db_uri):
    if args.network is None:
        args.network = DEFAULT_NETWORK
    print("\nCREATE wallet '%s' (%s network)" % (wallet_name, args.network))
    if args.create_multisig:
        if not isinstance(args.create_multisig, list) or len(args.create_multisig) < 2:
            clw_exit("Please enter multisig creation parameter in the following format: "
                     "<number-of-signatures> <number-of-signatures-required> "
                     "<key-0> <key-1> [<key-2> ... <key-n>]")
        try:
            sigs_total = int(args.create_multisig[0])
        except ValueError:
            clw_exit("Number of total signatures (first argument) must be a numeric value. %s" %
                     args.create_multisig[0])
        try:
            sigs_required = int(args.create_multisig[1])
        except ValueError:
            clw_exit("Number of signatures required (second argument) must be a numeric value. %s" %
                     args.create_multisig[1])
        key_list = args.create_multisig[2:]
        keys_missing = sigs_total - len(key_list)
        assert(keys_missing >= 0)
        if keys_missing:
            print("Not all keys provided, creating %d additional key(s)" % keys_missing)
            for _ in range(keys_missing):
                passphrase = get_passphrase(args)
                passphrase = ' '.join(passphrase)
                seed = binascii.hexlify(Mnemonic().to_seed(passphrase))
                key_list.append(HDKey.from_seed(seed, network=args.network))
        return HDWallet.create(wallet_name, key_list, sigs_required=sigs_required, network=args.network,
                               cosigner_id=args.cosigner_id, db_uri=db_uri, witness_type=args.witness_type)
    elif args.create_from_key:
        return HDWallet.create(wallet_name, args.create_from_key, network=args.network,
                               db_uri=db_uri, witness_type=args.witness_type)
    else:
        passphrase = args.passphrase
        if passphrase is None:
            passphrase = get_passphrase(args)
        elif not passphrase:
            passphrase = input("Enter Passphrase: ")
        if not isinstance(passphrase, list):
            passphrase = passphrase.split(' ')
        elif len(passphrase) == 1:
            passphrase = passphrase[0].split(' ')
        if len(passphrase) < 12:
            clw_exit("Please specify passphrase with 12 words or more")
        passphrase = ' '.join(passphrase)
        seed = binascii.hexlify(Mnemonic().to_seed(passphrase))
        hdkey = HDKey.from_seed(seed, network=args.network)
        return HDWallet.create(wallet_name, hdkey, network=args.network, witness_type=args.witness_type,
                               db_uri=db_uri)


def create_transaction(wlt, send_args, args):
    output_arr = []
    while send_args:
        if len(send_args) == 1:
            raise ValueError("Invalid number of transaction input use <address1> <amount1> ... <address_n> <amount_n>")
        try:
            amount = int(send_args[1])
        except ValueError:
            clw_exit("Amount must be a integer value: %s" % send_args[1])
        output_arr.append((send_args[0], amount))
        send_args = send_args[2:]
    return wlt.transaction_create(output_arr=output_arr, network=args.network, fee=args.fee, min_confirms=0)


def print_transaction(wt):
    tx_dict = {
        'network': wt.network.name, 'fee': wt.fee, 'raw': wt.raw_hex(), 'outputs': [{
            'address': o.address, 'value': o.value
        } for o in wt.outputs], 'inputs': [{
            'prev_hash': to_hexstring(i.prev_hash), 'output_n': struct.unpack('>I', i.output_n)[0],
            'address': i.address, 'signatures': [{
                'signature': s.hex(), 'sig_der': s.as_der_encoded(as_hex=True),
                'pub_key': s.public_key.public_hex,
            } for s in i.signatures], 'value': i.value
        } for i in wt.inputs]
    }
    pprint(tx_dict)


def clw_exit(msg=None):
    if msg:
        print(msg)
    sys.exit()


def main():
    print("Command Line Wallet - BitcoinLib %s\n" % BITCOINLIB_VERSION)
    # --- Parse commandline arguments ---
    args = parse_args()

    db_uri = args.database

    if args.generate_key:
        passphrase = get_passphrase(args)
        passphrase = ' '.join(passphrase)
        seed = binascii.hexlify(Mnemonic().to_seed(passphrase))
        hdkey = HDKey.from_seed(seed, network=args.network)
        print("Private Master key, to create multisig wallet on this machine:\n%s" % hdkey.wif_private())
        print("Public Master key, to share with other cosigner multisig wallets:\n%s" %
              hdkey.public_master(witness_type=args.witness_type, multisig=True).wif())
        print("Network: %s" % hdkey.network.name)
        clw_exit()

    # List wallets, then exit
    if args.list_wallets:
        print("BitcoinLib wallets:")
        for w in wallets_list(db_uri=db_uri):
            if 'parent_id' in w and w['parent_id']:
                continue
            print("[%d] %s (%s) %s" % (w['id'], w['name'], w['network'], w['owner']))
        clw_exit()

    # Delete specified wallet, then exit
    if args.wallet_remove:
        if not wallet_exists(args.wallet_name, db_uri=db_uri):
            clw_exit("Wallet '%s' not found" % args.wallet_name)
        inp = input("\nWallet '%s' with all keys and will be removed, without private key it cannot be restored."
                    "\nPlease retype exact name of wallet to proceed: " % args.wallet_name)
        if inp == args.wallet_name:
            if wallet_delete(args.wallet_name, force=True, db_uri=db_uri):
                clw_exit("\nWallet %s has been removed" % args.wallet_name)
            else:
                clw_exit("\nError when deleting wallet")
        else:
            clw_exit("\nSpecified wallet name incorrect")

    wlt = None
    if args.wallet_name and not args.wallet_name.isdigit() and not wallet_exists(args.wallet_name,
                                                                                 db_uri=db_uri):
        if not args.create_from_key and input(
                    "Wallet %s does not exist, create new wallet [yN]? " % args.wallet_name).lower() != 'y':
            clw_exit('Aborted')
        wlt = create_wallet(args.wallet_name, args, db_uri)
        args.wallet_info = True
    else:
        try:
            wlt = HDWallet(args.wallet_name, db_uri=db_uri)
            if args.passphrase is not None:
                print("WARNING: Using passphrase option for existing wallet ignored")
            if args.create_from_key is not None:
                print("WARNING: Using create_from_key option for existing wallet ignored")
        except WalletError as e:
            clw_exit("Error: %s" % e.msg)

    if wlt is None:
        clw_exit("Could not open wallet %s" % args.wallet_name)

    if args.import_private:
        if wlt.import_key(args.import_private):
            clw_exit("Private key imported")
        else:
            clw_exit("Failed to import key")

    if args.wallet_recreate:
        wallet_empty(args.wallet_name)
        print("Removed transactions and generated keys from this wallet")
    if args.update_utxos:
        wlt.utxos_update()
    if args.update_transactions:
        wlt.scan(scan_gap_limit=5)

    if args.export_private:
        if wlt.scheme == 'multisig':
            for w in wlt.cosigner:
                if w.main_key and w.main_key.is_private:
                    print(w.main_key.wif)
        elif not wlt.main_key or not wlt.main_key.is_private:
            print("No private key available for this wallet")
        else:
            print(wlt.main_key.wif)
        clw_exit()

    if args.network is None:
        args.network = wlt.network.name

    tx_import = None
    if args.import_tx_file:
        try:
            fn = args.import_tx_file
            f = open(fn, "r")
        except FileNotFoundError:
            clw_exit("File %s not found" % args.import_tx_file)
        try:
            tx_import = ast.literal_eval(f.read())
        except (ValueError, SyntaxError):
            tx_import = f.read()
    if args.import_tx:
        try:
            tx_import = ast.literal_eval(args.import_tx)
        except (ValueError, SyntaxError):
            tx_import = args.import_tx
    if tx_import:
        if isinstance(tx_import, dict):
            wt = wlt.transaction_import(tx_import)
        else:
            wt = wlt.transaction_import_raw(tx_import, network=args.network)
        wt.sign()
        if args.push:
            res = wt.send()
            if res:
                print("Transaction pushed to network. Transaction ID: %s" % wt.hash)
            else:
                print("Error creating transaction: %s" % wt.error)
        wt.info()
        print("Signed transaction:")
        print_transaction(wt)
        clw_exit()

    if args.receive:
        cosigner_id = args.receive
        if args.receive == -1:
            cosigner_id = None
        key = wlt.get_key(network=args.network, cosigner_id=cosigner_id)
        print("Receive address: %s" % key.address)
        if QRCODES_AVAILABLE:
            qrcode = pyqrcode.create(key.address)
            print(qrcode.terminal())
        else:
            print("Install qr code module to show QR codes: pip install pyqrcode")
        clw_exit()
    if args.create_transaction == []:
        clw_exit("Missing arguments for --create-transaction/-t option")
    if args.create_transaction:
        if args.fee_per_kb:
            clw_exit("Fee-per-kb option not allowed with --create-transaction")
        try:
            wt = create_transaction(wlt, args.create_transaction, args)
        except WalletError as e:
            clw_exit("Cannot create transaction: %s" % e.msg)
        wt.sign()
        print("Transaction created")
        wt.info()
        if args.push:
            wt.send()
            if wt.pushed:
                print("Transaction pushed to network. Transaction ID: %s" % wt.hash)
            else:
                print("Error creating transaction: %s" % wt.error)
        else:
            print("\nTransaction created but not send yet. Transaction dictionary for export: ")
            print_transaction(wt)
        clw_exit()
    if args.sweep:
        if args.fee:
            clw_exit("Fee option not allowed with --sweep")
        offline = True
        print("Sweep wallet. Send all funds to %s" % args.sweep)
        if args.push:
            offline = False
        wt = wlt.sweep(args.sweep, offline=offline, network=args.network, fee_per_kb=args.fee_per_kb)
        if not wt:
            clw_exit("Error occurred when sweeping wallet: %s. Are UTXO's available and updated?" % wt)
        wt.info()
        if args.push:
            if wt.pushed:
                print("Transaction pushed to network. Transaction ID: %s" % wt.hash)
            elif not wt:
                print("Cannot sweep wallet, are UTXO's updated and available?")
            else:
                print("Error sweeping wallet: %s" % wt.error)
        else:
            print("\nTransaction created but not send yet. Transaction dictionary for export: ")
            print_transaction(wt)
        clw_exit()

    # print("Updating wallet")
    if args.network == 'bitcoinlib_test':
        wlt.utxos_update()
    print("Wallet info for %s" % wlt.name)
    wlt.info()


if __name__ == '__main__':
    main()
