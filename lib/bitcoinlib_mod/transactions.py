# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    TRANSACTION class to create, verify and sign Transactions
#    © 2017 - 2020 February - 1200 Web Development <http://1200wd.com/>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from datetime import datetime
import json
import struct

from bitcoinlib.encoding import *
from bitcoinlib.config.opcodes import *
from bitcoinlib.keys import HDKey, Key, deserialize_address, Address, sign, verify, Signature
from bitcoinlib.networks import Network


_logger = logging.getLogger(__name__)


class TransactionError(Exception):
    """
    Handle Transaction class Exceptions
    """

    def __init__(self, msg=''):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg


def _transaction_deserialize(rawtx, network=DEFAULT_NETWORK):
    """
    Deserialize a raw transaction
    
    Returns a dictionary with list of input and output objects, locktime and version.
    
    Will raise an error if wrong number of inputs are found or if there are no output found.
    
    :param rawtx: Raw transaction as String, Byte or Bytearray
    :type rawtx: str, bytes, bytearray
    :param network: Network code, i.e. 'bitcoin', 'testnet', 'litecoin', etc. Leave emtpy for default network
    :type network: str, Network

    :return Transaction:
    """

    rawtx = to_bytes(rawtx)
    version = rawtx[0:4][::-1]
    coinbase = False
    flag = None
    witness_type = 'legacy'
    cursor = 4
    if rawtx[4:5] == b'\0':
        flag = rawtx[5:6]
        if flag == b'\1':
            witness_type = 'segwit'
        cursor += 2
    n_inputs, size = varbyteint_to_int(rawtx[cursor:cursor+9])
    cursor += size
    inputs = []
    if not isinstance(network, Network):
        network = Network(network)
    for n in range(0, n_inputs):
        inp_hash = rawtx[cursor:cursor + 32][::-1]
        if not len(inp_hash):
            raise TransactionError("Input transaction hash not found. Probably malformed raw transaction")
        if inp_hash == 32 * b'\0':
            coinbase = True
        output_n = rawtx[cursor + 32:cursor + 36][::-1]
        cursor += 36
        unlocking_script_size, size = varbyteint_to_int(rawtx[cursor:cursor + 9])
        cursor += size
        unlocking_script = rawtx[cursor:cursor + unlocking_script_size]
        inp_type = 'legacy'
        if witness_type == 'segwit' and not unlocking_script_size:
            inp_type = 'segwit'
        cursor += unlocking_script_size
        sequence_number = rawtx[cursor:cursor + 4]
        cursor += 4
        inputs.append(Input(prev_hash=inp_hash, output_n=output_n, unlocking_script=unlocking_script,
                            witness_type=inp_type, sequence=sequence_number, index_n=n, network=network))
    if len(inputs) != n_inputs:
        raise TransactionError("Error parsing inputs. Number of tx specified %d but %d found" % (n_inputs, len(inputs)))

    outputs = []
    n_outputs, size = varbyteint_to_int(rawtx[cursor:cursor + 9])
    cursor += size
    output_total = 0
    for n in range(0, n_outputs):
        value = change_base(rawtx[cursor:cursor + 8][::-1], 256, 10)
        cursor += 8
        lock_script_size, size = varbyteint_to_int(rawtx[cursor:cursor + 9])
        cursor += size
        lock_script = rawtx[cursor:cursor + lock_script_size]
        cursor += lock_script_size
        outputs.append(Output(value=value, lock_script=lock_script, network=network, output_n=n))
        output_total += value
    if not outputs:
        raise TransactionError("Error no outputs found in this transaction")
    if witness_type == 'segwit':
        for n in range(0, len(inputs)):
            n_items, size = varbyteint_to_int(rawtx[cursor:cursor + 9])
            cursor += size
            witnesses = []
            for m in range(0, n_items):
                witness = b'\0'
                item_size, size = varbyteint_to_int(rawtx[cursor:cursor + 9])
                if item_size:
                    witness = rawtx[cursor:cursor + item_size + size]
                cursor += item_size + size
                witnesses.append(witness)
            if witnesses and not coinbase:
                script_type = inputs[n].script_type
                witness_script_type = 'sig_pubkey'
                signatures = []
                keys = []
                sigs_required = 1
                public_hash = b''
                for witness in witnesses:
                    if witness == b'\0':
                        continue
                    item_size, size = varbyteint_to_int(witness)
                    if 70 <= item_size <= 74 and witness[1:2] == b'\x30':  # witness is DER encoded signature
                        signatures.append(witness[1:])
                    elif item_size == 33 and len(witness) == 33 + size and len(signatures) == 1:  # key from sig_pk
                        keys.append(witness[1:])
                    elif len(witness) == item_size + size:  # Redeemscript
                        rsds = script_deserialize(witness, script_types=['multisig'])
                        if not rsds['script_type'] == 'multisig':
                            raise TransactionError("Could not parse witnesses in transaction. Multisig redeemscript "
                                                   "expected")
                        # FIXME: Do not mixup naming signatures and keys
                        keys = rsds['signatures']
                        sigs_required = rsds['number_of_sigs_m']
                        witness_script_type = 'p2sh'
                        script_type = 'p2sh_multisig'
                    else:
                        raise TransactionError("Could not parse witnesses in transaction")

                inp_witness_type = inputs[n].witness_type
                usd = script_deserialize(inputs[n].unlocking_script, locking_script=True)

                if usd['script_type'] == "p2wpkh" and witness_script_type == 'sig_pubkey':
                    inp_witness_type = 'p2sh-segwit'
                    script_type = 'p2sh_p2wpkh'
                elif usd['script_type'] == "p2wsh" and witness_script_type == 'p2sh':
                    inp_witness_type = 'p2sh-segwit'
                    script_type = 'p2sh_p2wsh'
                inputs[n] = Input(prev_hash=inputs[n].prev_hash, output_n=inputs[n].output_n, keys=keys,
                                  unlocking_script_unsigned=inputs[n].unlocking_script_unsigned,
                                  unlocking_script=inputs[n].unlocking_script, sigs_required=sigs_required,
                                  signatures=signatures, witness_type=inp_witness_type, script_type=script_type,
                                  sequence=inputs[n].sequence, index_n=inputs[n].index_n, public_hash=public_hash,
                                  network=inputs[n].network)
    if len(rawtx[cursor:]) != 4:
        raise TransactionError("Error when deserializing raw transaction, bytes left for locktime must be 4 not %d" %
                               len(rawtx[cursor:]))
    locktime = change_base(rawtx[cursor:cursor + 4][::-1], 256, 10)

    return Transaction(inputs, outputs, locktime, version, network, size=len(rawtx), output_total=output_total,
                       coinbase=coinbase, flag=flag, witness_type=witness_type, rawtx=to_hexstring(rawtx))


def script_deserialize(script, script_types=None, locking_script=None, size_bytes_check=True):
    """
    Deserialize a script: determine type, number of signatures and script data.
    
    :param script: Raw script
    :type script: str, bytes, bytearray
    :param script_types: Limit script type determination to this list. Leave to default None to search in all script types.
    :type script_types: list
    :param locking_script: Only deserialize locking scripts. Specify False to only deserialize for unlocking scripts. Default is None for both
    :type locking_script: bool
    :param size_bytes_check: Check if script or signature starts with size bytes and remove size bytes before parsing. Default is True
    :type size_bytes_check: bool

    :return list: With this items: [script_type, data, number_of_sigs_n, number_of_sigs_m] 
    """

    def _parse_data(scr, max_items=None, redeemscript_expected=False, item_length=0):
        scr = to_bytes(scr)
        items = []
        total_length = 0
        if 70 <= len(scr) <= 74 and scr[:1] == b'\x30':
            return [scr], len(scr)
        while len(scr) and (max_items is None or max_items > len(items)):
            itemlen, size = varbyteint_to_int(scr[0:9])
            if item_length and itemlen != item_length:
                break
            # TODO: Rethink and rewrite this:
            if not item_length and itemlen not in [20, 33, 65, 70, 71, 72, 73]:
                break
            if redeemscript_expected and len(scr[itemlen + 1:]) < 20:
                break
            items.append(scr[1:itemlen + 1])
            total_length += itemlen + size
            scr = scr[itemlen + 1:]
        return items, total_length

    def _get_empty_data():
        return {'script_type': '', 'keys': [], 'signatures': [], 'hashes': [], 'redeemscript': b'',
                'number_of_sigs_n': 1, 'number_of_sigs_m': 1, 'locktime_cltv': None, 'locktime_csv': None, 'result': ''}

    def _parse_script(script):
        found = False
        cur = 0
        data = _get_empty_data()
        for script_type in script_types:
            cur = 0
            try:
                ost = SCRIPT_TYPES_UNLOCKING[script_type]
            except KeyError:
                ost = SCRIPT_TYPES_LOCKING[script_type]
            data = _get_empty_data()
            data['script_type'] = script_type
            found = True
            for ch in ost:
                if cur >= len(script):
                    found = False
                    break
                cur_char = script[cur]
                if sys.version < '3':
                    if not isinstance(script, bytearray):
                        cur_char = ord(script[cur])
                if ch[:4] == 'hash':
                    hash_length = 0
                    if len(ch) > 5:
                        hash_length = int(ch.split("-")[1])
                    s, total_length = _parse_data(script[cur:], 1, item_length=hash_length)
                    if not s:
                        found = False
                        break
                    data['hashes'] += s
                    cur += total_length
                elif ch == 'signature':
                    signature_length = 0
                    s, total_length = _parse_data(script[cur:], 1, item_length=signature_length)
                    if not s:
                        found = False
                        break
                    data['signatures'] += s
                    cur += total_length
                elif ch == 'public_key':
                    pk_size, size = varbyteint_to_int(script[cur:cur + 9])
                    key = script[cur + size:cur + size + pk_size]
                    if not key:
                        found = False
                        break
                    data['keys'].append(key)
                    cur += size + pk_size
                elif ch == 'OP_RETURN':
                    if cur_char == opcodes['OP_RETURN'] and cur == 0:
                        data.update({'op_return': script[cur + 1:]})
                        cur = len(script)
                        found = True
                        break
                    else:
                        found = False
                        break
                elif ch == 'multisig':  # one or more signatures
                    redeemscript_expected = False
                    if 'redeemscript' in ost:
                        redeemscript_expected = True
                    s, total_length = _parse_data(script[cur:], redeemscript_expected=redeemscript_expected)
                    if not s:
                        found = False
                        break
                    data['signatures'] += s
                    cur += total_length
                elif ch == 'redeemscript':
                    size_byte = 0
                    if script[cur:cur + 1] == b'\x4c':
                        size_byte = 1
                    elif script[cur:cur + 1] == b'\x4d':
                        size_byte = 2
                    elif script[cur:cur + 1] == b'\x4e':
                        size_byte = 3
                    data['redeemscript'] = script[cur + 1 + size_byte:]
                    data2 = script_deserialize(data['redeemscript'], locking_script=True)
                    if 'signatures' not in data2 or not data2['signatures']:
                        found = False
                        break
                    data['keys'] = data2['signatures']
                    data['number_of_sigs_m'] = data2['number_of_sigs_m']
                    data['number_of_sigs_n'] = data2['number_of_sigs_n']
                    cur = len(script)
                elif ch == 'push_size':
                    push_size, size = varbyteint_to_int(script[cur:cur + 9])
                    found = bool(len(script[cur:]) - size == push_size)
                    if not found:
                        break
                elif ch == 'op_m':
                    if cur_char in OP_N_CODES:
                        data['number_of_sigs_m'] = cur_char - opcodes['OP_1'] + 1
                    else:
                        found = False
                        break
                    cur += 1
                elif ch == 'op_n':
                    if cur_char in OP_N_CODES:
                        data['number_of_sigs_n'] = cur_char - opcodes['OP_1'] + 1
                    else:
                        found = False
                        break
                    if data['number_of_sigs_m'] > data['number_of_sigs_n']:
                        raise TransactionError("Number of signatures to sign (%s) is higher then actual "
                                               "amount of signatures (%s)" %
                                               (data['number_of_sigs_m'], data['number_of_sigs_n']))
                    if len(data['signatures']) > int(data['number_of_sigs_n']):
                        raise TransactionError("%d signatures found, but %s sigs expected" %
                                               (len(data['signatures']), data['number_of_sigs_n']))
                    cur += 1
                elif ch == 'SIGHASH_ALL':
                    pass
                elif ch == 'locktime_cltv':
                    if len(script) < 4:
                        found = False
                        break
                    data['locktime_cltv'] = struct.unpack('<L', script[cur:cur + 4])[0]
                    cur += 4
                elif ch == 'locktime_csv':
                    if len(script) < 4:
                        found = False
                        break
                    data['locktime_csv'] = struct.unpack('<L', script[cur:cur + 4])[0]
                    cur += 4
                else:
                    try:
                        if cur_char == opcodes[ch]:
                            cur += 1
                        else:
                            found = False
                            data = _get_empty_data()
                            break
                    except IndexError:
                        raise TransactionError("Opcode %s not found [type %s]" % (ch, script_type))
            if found and not len(script[cur:]):  # Found is True and no remaining script to parse
                break

        if found and not len(script[cur:]):
            return data, script[cur:]
        data = _get_empty_data()
        data['result'] = 'Script not recognised'
        return data, ''

    data = _get_empty_data()
    script = to_bytes(script)
    if not script:
        data.update({'result': 'Empty script'})
        return data

    # Check if script starts with size byte
    if size_bytes_check:
        script_size, size = varbyteint_to_int(script[0:9])
        if len(script[1:]) == script_size:
            data = script_deserialize(script[1:], script_types, locking_script, size_bytes_check=False)
            if 'result' in data and data['result'][:22] not in \
                    ['Script not recognised', 'Empty script', 'Could not parse script']:
                return data

    if script_types is None:
        if locking_script is None:
            script_types = dict(SCRIPT_TYPES_UNLOCKING, **SCRIPT_TYPES_LOCKING)
        elif locking_script:
            script_types = SCRIPT_TYPES_LOCKING
        else:
            script_types = SCRIPT_TYPES_UNLOCKING
    elif not isinstance(script_types, list):
        script_types = [script_types]

    locktime_cltv = 0
    locktime_csv = 0
    while len(script):
        begin_script = script
        data, script = _parse_script(script)
        if begin_script == script:
            break
        if script and data['script_type'] == 'locktime_cltv':
            locktime_cltv = data['locktime_cltv']
        if script and data['script_type'] == 'locktime_csv':
            locktime_csv = data['locktime_csv']
    if data and data['result'] != 'Script not recognised':
        data['locktime_cltv'] = locktime_cltv
        data['locktime_csv'] = locktime_csv
        return data

    wrn_msg = "Could not parse script, unrecognized script"
    # _logger.debug(wrn_msg)
    data = _get_empty_data()
    data['result'] = wrn_msg
    return data


def script_to_string(script):
    """
    Convert script to human readable string format with OP-codes, signatures, keys, etc
    
    >>> script = '76a914c7402ab295a0eb8897ff5b8fbd5276c2d9d2340b88ac'
    >>> script_to_string(script)
    'OP_DUP OP_HASH160 hash-20 OP_EQUALVERIFY OP_CHECKSIG'

    :param script: A locking or unlocking script
    :type script: bytes, str

    :return str: 
    """

    script = to_bytes(script)
    data = script_deserialize(script)
    if not data or data['script_type'] == 'empty':
        return ""
    sigs = ' '.join([to_hexstring(i) for i in data['signatures']])

    try:
        scriptstr = SCRIPT_TYPES_LOCKING[data['script_type']]
    except KeyError:
        scriptstr = SCRIPT_TYPES_UNLOCKING[data['script_type']]
    scriptstr = [sigs if x in ['signature', 'multisig', 'return_data'] else x for x in scriptstr]
    if 'redeemscript' in data and data['redeemscript']:
        redeemscript_str = script_to_string(data['redeemscript'])
        scriptstr = [redeemscript_str if x == 'redeemscript' else x for x in scriptstr]
    scriptstr = [opcodenames[80 + int(data['number_of_sigs_m'])] if x == 'op_m' else x for x in scriptstr]
    scriptstr = [opcodenames[80 + int(data['number_of_sigs_n'])] if x == 'op_n' else x for x in scriptstr]

    return ' '.join(scriptstr)


def _serialize_multisig_redeemscript(public_key_list, n_required=None):
    # Serialize m-to-n multisig script. Needs a list of public keys
    for key in public_key_list:
        if not isinstance(key, (str, bytes)):
            raise TransactionError("Item %s in public_key_list is not of type string or bytes")
    if n_required is None:
        n_required = len(public_key_list)

    script = int_to_varbyteint(opcodes['OP_1'] + n_required - 1)
    for key in public_key_list:
        script += varstr(key)
    script += int_to_varbyteint(opcodes['OP_1'] + len(public_key_list) - 1)
    script += b'\xae'  # 'OP_CHECKMULTISIG'

    return script


def serialize_multisig_redeemscript(key_list, n_required=None, compressed=True):
    """
    Create a multisig redeemscript used in a p2sh.

    Contains the number of signatures, followed by the list of public keys and the OP-code for the number of signatures required.

    :param key_list: List of public keys
    :type key_list: Key, list
    :param n_required: Number of required signatures
    :type n_required: int
    :param compressed: Use compressed public keys?
    :type compressed: bool

    :return bytes: A multisig redeemscript
    """

    if not key_list:
        return b''
    if not isinstance(key_list, list):
        raise TransactionError("Argument public_key_list must be of type list")
    if len(key_list) > 15:
        raise TransactionError("Redeemscripts with more then 15 keys are non-standard and could result in "
                               "locked up funds")
    public_key_list = []
    for k in key_list:
        if isinstance(k, Key):
            if compressed:
                public_key_list.append(k.public_byte)
            else:
                public_key_list.append(k.public_uncompressed_byte)
        elif len(k) == 65 and k[0:1] == b'\x04' or len(k) == 33 and k[0:1] in [b'\x02', b'\x03']:
            public_key_list.append(k)
        elif len(k) == 132 and k[0:2] == '04' or len(k) == 66 and k[0:2] in ['02', '03']:
            public_key_list.append(to_bytes(k))
        else:
            kobj = Key(k)
            if compressed:
                public_key_list.append(kobj.public_byte)
            else:
                public_key_list.append(kobj.public_uncompressed_byte)

    return _serialize_multisig_redeemscript(public_key_list, n_required)


def _p2sh_multisig_unlocking_script(sigs, redeemscript, hash_type=None, as_list=False):
    usu = b'\x00'
    if as_list:
        usu = [usu]
    if not isinstance(sigs, list):
        sigs = [sigs]
    for sig in sigs:
        s = sig
        if hash_type:
            s += struct.pack('B', hash_type)
        if as_list:
            usu.append(s)
        else:
            usu += varstr(s)

    rs_size = b''
    size_byte = b''
    if not as_list:
        rs_size = int_to_varbyteint(len(redeemscript))
        if len(redeemscript) >= 76:
            if len(rs_size) == 1:
                size_byte = b'\x4c'
            elif len(rs_size) == 2:
                size_byte = b'\x4d'
            else:
                size_byte = b'\x4e'

    redeemscript_str = size_byte + rs_size + redeemscript
    if as_list:
        usu.append(redeemscript_str)
    else:
        usu += redeemscript_str
    return usu


def script_add_locktime_cltv(locktime_cltv, script):
    lockbytes = opcode('OP_CHECKLOCKTIMEVERIFY') + opcode('OP_DROP')
    if script and len(script) > 6:
        if script[4:6] == lockbytes:
            return script
    return struct.pack('<L', locktime_cltv) + lockbytes + script


def script_add_locktime_csv(locktime_csv, script):
    lockbytes = opcode('OP_CHECKSEQUENCEVERIFY') + opcode('OP_DROP')
    if script and len(script) > 6:
        if script[4:6] == lockbytes:
            return script
    return struct.pack('<L', locktime_csv) + lockbytes + script


def get_unlocking_script_type(locking_script_type, witness_type='legacy', multisig=False):
    """
    Specify locking script type and get corresponding script type for unlocking script

    >>> get_unlocking_script_type('p2wsh')
    'p2sh_multisig'

    :param locking_script_type: Locking script type. I.e.: p2pkh, p2sh, p2wpkh, p2wsh
    :type locking_script_type: str
    :param witness_type: Type of witness: legacy or segwit. Default is legacy
    :type witness_type: str
    :param multisig: Is multisig script or not? Default is False
    :type multisig: bool

    :return str: Unlocking script type such as sig_pubkey or p2sh_multisig
    """

    if locking_script_type in ['p2pkh', 'p2wpkh']:
        return 'sig_pubkey'
    elif locking_script_type == 'p2wsh' or (witness_type == 'legacy' and multisig):
        return 'p2sh_multisig'
    elif locking_script_type == 'p2sh':
        if not multisig:
            return 'sig_pubkey'
        else:
            return 'p2sh_multisig'
    elif locking_script_type == 'p2pk':
        return 'signature'
    else:
        raise TransactionError("Unknown locking script type %s" % locking_script_type)


class Input(object):
    """
    Transaction Input class, used by Transaction class
    
    An Input contains a reference to an UTXO or Unspent Transaction Output (prev_hash + output_n).
    To spent the UTXO an unlocking script can be included to prove ownership.
    
    Inputs are verified by the Transaction class.
    """

    def __init__(self, prev_hash, output_n, keys=None, signatures=None, public_hash=b'', unlocking_script=b'',
                 unlocking_script_unsigned=None, script_type=None, address='',
                 sequence=0xffffffff, compressed=None, sigs_required=None, sort=False, index_n=0,
                 value=0, double_spend=False, locktime_cltv=None, locktime_csv=None, key_path='', witness_type=None,
                 encoding=None, network=DEFAULT_NETWORK):
        """
        Create a new transaction input
        
        :param prev_hash: Transaction hash of the UTXO (previous output) which will be spent.
        :type prev_hash: bytes, hexstring
        :param output_n: Output number in previous transaction.
        :type output_n: bytes, int
        :param keys: A list of Key objects or public / private key string in various formats. If no list is provided but a bytes or string variable, a list with one item will be created. Optional
        :type keys: list (bytes, str, Key)
        :param signatures: Specify optional signatures
        :type signatures: list (bytes, str, Signature)
        :param public_hash: Public key or script hash. Specify if key is not available
        :type public_hash: bytes, str
        :param unlocking_script: Unlocking script (scriptSig) to prove ownership. Optional
        :type unlocking_script: bytes, hexstring
        :param unlocking_script_unsigned: Unlocking script for signing transaction
        :type unlocking_script_unsigned: bytes, hexstring
        :param script_type: Type of unlocking script used, i.e. p2pkh or p2sh_multisig. Default is p2pkh
        :type script_type: str
        :param address: Address string or object for input
        :type address: str, Address
        :param sequence: Sequence part of input, you normally do not have to touch this
        :type sequence: bytes, int
        :param compressed: Use compressed or uncompressed public keys. Default is compressed
        :type compressed: bool
        :param sigs_required: Number of signatures required for a p2sh_multisig unlocking script
        :type sigs_required: int
        :param sort: Sort public keys according to BIP0045 standard. Default is False to avoid unexpected change of key order.
        :type sort: boolean
        :param index_n: Index of input in transaction. Used by Transaction class.
        :type index_n: int
        :param value: Value of input in smallest denominator, i.e. sathosis
        :type value: int
        :param double_spend: Is this input also spend in another transaction
        :type double_spend: bool
        :param locktime_cltv: Check Lock Time Verify value. Script level absolute time lock for this input
        :type locktime_cltv: int
        :param locktime_csv: Check Sequency Verify value.
        :type locktime_csv: int
        :param key_path: Key path of input key as BIP32 string or list
        :type key_path: str, list
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty for default
        :type encoding: str
        :param network: Network, leave empty for default
        :type network: str, Network
        """

        self.prev_hash = to_bytes(prev_hash)
        self.output_n = output_n
        if isinstance(output_n, numbers.Number):
            self.output_n_int = output_n
            self.output_n = struct.pack('>I', output_n)
        else:
            self.output_n_int = struct.unpack('>I', output_n)[0]
            self.output_n = output_n
        self.unlocking_script = b'' if unlocking_script is None else to_bytes(unlocking_script)
        self.unlocking_script_unsigned = b'' if unlocking_script_unsigned is None \
            else to_bytes(unlocking_script_unsigned)
        if isinstance(sequence, numbers.Number):
            self.sequence = sequence
        else:
            self.sequence = struct.unpack('<I', sequence)[0]
        self.compressed = compressed
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        self.index_n = index_n
        self.value = value
        if not keys:
            keys = []
        self.keys = []
        if not isinstance(keys, list):
            keys = [keys]
        self.public_hash = public_hash
        if not signatures:
            signatures = []
        if not isinstance(signatures, list):
            signatures = [signatures]
        self.sort = sort
        if isinstance(address, Address):
            self.address = address.address
            self.encoding = address.encoding
            self.network = address.network
            self.script_type = address.script_type
        else:
            self.address = address
        self.signatures = []
        self.redeemscript = b''
        self.script_type = script_type
        if self.prev_hash == b'\0' * 32:
            self.script_type = 'coinbase'
        if not sigs_required:
            if self.script_type == 'p2sh_multisig':
                # raise TransactionError("Please specify number of signatures required (sigs_required) parameter")
                pass
            else:
                sigs_required = 1
        self.double_spend = double_spend
        self.locktime_cltv = locktime_cltv
        self.locktime_csv = locktime_csv
        self.witness_type = witness_type
        if encoding is None:
            self.encoding = 'base58'
            if self.witness_type == 'segwit':
                self.encoding = 'bech32'
        else:
            self.encoding = encoding
        self.valid = None
        self.key_path = key_path
        self.witnesses = []
        self.script_code = b''

        # If unlocking script is specified extract keys, signatures, type from script
        if self.unlocking_script and self.script_type != 'coinbase' and not signatures:
            us_dict = script_deserialize(self.unlocking_script)
            if not us_dict:  # or us_dict['script_type'] in ['unknown', 'empty']
                raise TransactionError("Could not parse unlocking script (%s)" % to_hexstring(self.unlocking_script))
            if us_dict['script_type'] not in ['', 'unknown', 'empty']:
                self.sigs_required = us_dict['number_of_sigs_n']
                self.redeemscript = us_dict['redeemscript']
                signatures += us_dict['signatures']
                keys += us_dict['keys']
                sigs_required = us_dict['number_of_sigs_m']
                if not signatures and not self.public_hash:
                    self.public_hash = us_dict['hashes'][0]
                # Determine locking script type for unlocking script type
                if not self.script_type:
                    self.script_type = us_dict['script_type']
                    if us_dict['script_type'] == 'p2wsh':
                        self.script_type = 'p2sh_p2wsh'
                    elif us_dict['script_type'] == 'p2wpkh':
                        self.script_type = 'p2sh_p2wpkh'
        elif unlocking_script_unsigned and not signatures:
            ls_dict = script_deserialize(unlocking_script_unsigned, locking_script=True)
            if ls_dict['hashes']:
                self.public_hash = ls_dict['hashes'][0]
                if ls_dict['script_type'] in ['p2wpkh', 'p2wsh']:
                    self.witness_type = 'segwit'
                self.script_type = get_unlocking_script_type(ls_dict['script_type'])
        self.sigs_required = sigs_required
        if self.witness_type is None or self.witness_type == 'legacy':
            if self.script_type in ['p2wpkh', 'p2wsh']:
                self.witness_type = 'segwit'
            elif self.script_type in ['p2sh_p2wpkh', 'p2sh_p2wsh']:
                self.witness_type = 'p2sh-segwit'
            else:
                self.witness_type = 'legacy'
        elif self.witness_type == 'segwit' and self.script_type == 'sig_pubkey' and encoding is None:
            self.encoding = 'bech32'
        if not self.script_type:
            self.script_type = 'sig_pubkey'

        for key in keys:
            if not isinstance(key, Key):
                kobj = Key(key, network=network)
            else:
                kobj = key
            if kobj not in self.keys:
                # if self.compressed is not None and kobj.compressed != self.compressed:
                #     _logger.warning("Key compressed is %s but Input class compressed argument is %s " %
                #                     (kobj.compressed, self.compressed))
                self.compressed = kobj.compressed
                self.keys.append(kobj)
        if self.compressed is None:
            self.compressed = True
        if self.sort:
            self.keys.sort(key=lambda k: k.public_byte)
        for sig in signatures:
            if not isinstance(sig, Signature):
                try:
                    sig = Signature.from_str(sig)
                except Exception as e:
                    _logger.error("Could not parse signature %s in Input. Error: %s" % (to_hexstring(sig), e))
                    continue
            if sig.as_der_encoded() not in [x.as_der_encoded() for x in self.signatures]:
                self.signatures.append(sig)
        self.update_scripts()

    # TODO: Remove / replace?
    # def sequence_timelock_blocks(self, blocks):
    #     if blocks > SEQUENCE_LOCKTIME_MASK:
    #         raise TransactionError("Number of nSequence timelock blocks exceeds %d" % SEQUENCE_LOCKTIME_MASK)
    #     self.sequence = blocks
    #
    # def sequence_timelock_time(self, seconds):
    #     if seconds % 512:
    #         raise TransactionError("Seconds must be a multiply of 512")
    #     if seconds > SEQUENCE_LOCKTIME_MASK:
    #         raise TransactionError("Number of relative nSeqence timelock seconds exceeds %d" % SEQUENCE_LOCKTIME_MASK)
    #     self.sequence = seconds // 512 + SEQUENCE_LOCKTIME_TYPE_FLAG

    def update_scripts(self, hash_type=SIGHASH_ALL):
        """
        Method to update Input scripts.

        Creates or updates unlocking script, witness script for segwit inputs, multisig redeemscripts and
        locktime scripts. This method is called when initializing a Input class or when signing an input.

        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int

        :return bool: Always returns True when method is completed
        """

        addr_data = b''
        unlock_script = b''
        if self.script_type in ['sig_pubkey', 'p2sh_p2wpkh']:
            if not self.keys and not self.public_hash:
                if self.unlocking_script_unsigned:
                    script_dict = script_deserialize(self.unlocking_script_unsigned)
                    if script_dict['script_type'] == 'p2pkh':
                        self.public_hash = script_dict['hashes'][0]
                    else:
                        return
                else:
                    return
            if not self.public_hash:
                self.public_hash = self.keys[0].hash160
            self.script_code = b'\x76\xa9\x14' + self.public_hash + b'\x88\xac'
            self.unlocking_script_unsigned = self.script_code
            self.address = Address(hashed_data=self.public_hash, encoding=self.encoding, network=self.network,
                                   script_type=self.script_type, witness_type=self.witness_type).address
            self.witnesses = []
            if self.signatures and self.keys:
                self.witnesses = [self.signatures[0].as_der_encoded() + struct.pack('B', hash_type), self.keys[0].public_byte]
                unlock_script = b''.join([bytes(varstr(w)) for w in self.witnesses])
            if self.witness_type == 'p2sh-segwit':
                self.unlocking_script = varstr(b'\0' + varstr(self.public_hash))
            elif self.witness_type == 'segwit':
                self.unlocking_script = b''
            elif unlock_script != b'':
                self.unlocking_script = unlock_script
        elif self.script_type in ['p2sh_multisig', 'p2sh_p2wsh']:
            # if not self.keys and not self.public_hash:
            #     raise TransactionError("Please provide keys to append multisig transaction input")
            if not self.redeemscript and self.keys:
                self.redeemscript = serialize_multisig_redeemscript(self.keys, n_required=self.sigs_required,
                                                                    compressed=self.compressed)
            if self.redeemscript:
                if self.witness_type == 'segwit' or self.witness_type == 'p2sh-segwit':
                    self.public_hash = hashlib.sha256(self.redeemscript).digest()
                else:
                    self.public_hash = hash160(self.redeemscript)
            if not self.address and self.public_hash:
                self.address = Address(hashed_data=self.public_hash, encoding=self.encoding, network=self.network,
                                       script_type=self.script_type, witness_type=self.witness_type).address
            self.unlocking_script_unsigned = self.redeemscript

            if self.redeemscript and self.keys:
                n_tag = self.redeemscript[0:1]
                if not isinstance(n_tag, int):
                    n_tag = struct.unpack('B', n_tag)[0]
                self.sigs_required = n_tag - 80
                signatures = [s.as_der_encoded() for s in self.signatures[:self.sigs_required]]
                if b'' in signatures:
                    raise TransactionError("Empty signature found in signature list when signing. "
                                           "Is DER encoded version of signature defined?")
                if len(signatures):
                    us_as_list = False
                    if self.witness_type in ['segwit', 'p2sh-segwit']:
                        us_as_list = True
                    unlock_script = _p2sh_multisig_unlocking_script(signatures, self.redeemscript, hash_type,
                                                                    as_list=us_as_list)
                if self.witness_type == 'segwit':
                    script_code = b''
                    for k in self.keys:
                        script_code += varstr(k.public_byte) + b'\xad\xab'
                    if len(script_code) > 3:
                        script_code = script_code[:-2] + b'\xac'
                    self.script_code = script_code
                    if signatures:
                        self.witnesses = unlock_script
                elif self.witness_type == 'p2sh-segwit':
                    self.unlocking_script = varstr(b'\0' + varstr(self.public_hash))
                    self.script_code = self.unlocking_script
                    if signatures:
                        self.witnesses = unlock_script
                elif unlock_script != b'':
                    self.unlocking_script = unlock_script
        elif self.script_type == 'signature':
            if self.keys:
                self.script_code = self.keys[0].public_byte + b'\xac'
                self.unlocking_script_unsigned = self.script_code
            if self.signatures:
                self.unlocking_script = varstr(self.signatures[0].as_der_encoded() + struct.pack('B', hash_type))
        elif self.script_type != 'coinbase':
            raise TransactionError("Unknown unlocking script type %s for input %d" % (self.script_type, self.index_n))
        if addr_data:
            self.address = Address(addr_data, encoding=self.encoding, network=self.network,
                                   script_type=self.script_type, witness_type=self.witness_type).address

        if self.locktime_cltv:
            self.unlocking_script_unsigned = script_add_locktime_cltv(self.locktime_cltv,
                                                                      self.unlocking_script_unsigned)
            self.unlocking_script = script_add_locktime_cltv(self.locktime_cltv, self.unlocking_script)
        elif self.locktime_csv:
            self.unlocking_script_unsigned = script_add_locktime_csv(self.locktime_csv, self.unlocking_script_unsigned)
            self.unlocking_script = script_add_locktime_csv(self.locktime_csv, self.unlocking_script)
        return True

    def as_dict(self):
        """
        Get transaction input information in json format
        
        :return dict: Json with output_n, prev_hash, output_n, type, address, public_key, public_hash, unlocking_script and sequence
        """

        pks = []
        for k in self.keys:
            pks.append(k.public_hex)
        if len(self.keys) == 1:
            pks = pks[0]
        return {
            'index_n': self.index_n,
            'prev_hash': to_hexstring(self.prev_hash),
            'output_n': self.output_n_int,
            'script_type': self.script_type,
            'address': self.address,
            'value': self.value,
            'public_keys': pks,
            'compressed': self.compressed,
            'encoding': self.encoding,
            'double_spend': self.double_spend,
            'script': to_hexstring(self.unlocking_script),
            'redeemscript': to_hexstring(self.redeemscript),
            'sequence': self.sequence,
            'signatures': [s.hex() for s in self.signatures],
            'sigs_required': self.sigs_required,
            'locktime_cltv': self.locktime_cltv,
            'locktime_csv': self.locktime_csv, 'public_hash': to_hexstring(self.public_hash),
            'script_code': to_hexstring(self.script_code),
            'unlocking_script': to_hexstring(self.unlocking_script),
            'unlocking_script_unsigned': to_hexstring(self.unlocking_script_unsigned),
            'witness_type': self.witness_type,
            'witness': to_hexstring(b''.join(self.witnesses)),
            'sort': self.sort,
            'valid': self.valid,
        }

    def __repr__(self):
        return "<Input(prev_hash='%s', output_n=%d, address='%s', index_n=%s, type='%s')>" % \
               (to_hexstring(self.prev_hash), self.output_n_int, self.address, self.index_n, self.script_type)


class Output(object):
    """
    Transaction Output class, normally part of Transaction class.
    
    Contains the amount and destination of a transaction.
    """

    def __init__(self, value, address='', public_hash=b'', public_key=b'', lock_script=b'', spent=False,
                 output_n=0, script_type=None, encoding=None, network=DEFAULT_NETWORK):
        """
        Create a new transaction output
        
        An transaction outputs locks the specified amount to a public key. Anyone with the private key can unlock
        this output.
        
        The transaction output class contains an amount and the destination which can be provided either as address, 
        public key, public key hash or a locking script. Only one needs to be provided as the they all can be derived 
        from each other, but you can provide as much attributes as you know to improve speed.
        
        :param value: Amount of output in smallest denominator of currency, for example satoshi's for bitcoins
        :type value: int
        :param address: Destination address of output. Leave empty to derive from other attributes you provide. An instance of an Address or HDKey class is allowed as argument.
        :type address: str, Address, HDKey
        :param public_hash: Hash of public key or script
        :type public_hash: bytes, str
        :param public_key: Destination public key
        :type public_key: bytes, str
        :param lock_script: Locking script of output. If not provided a default unlocking script will be provided with a public key hash.
        :type lock_script: bytes, str
        :param spent: Is output already spent? Default is False
        :type spent: bool
        :param output_n: Output index number, default is 0. Index number has to be unique per transaction and 0 for first output, 1 for second, etc
        :type output_n: int
        :param script_type: Script type of output (p2pkh, p2sh, segwit p2wpkh, etc). Extracted from lock_script if provided.
        :type script_type: str
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty to derive from address or default base58 encoding
        :type encoding: str
        :param network: Network, leave empty for default
        :type network: str, Network
        """

        if not (address or public_hash or public_key or lock_script):
            raise TransactionError("Please specify address, lock_script, public key or public key hash when "
                                   "creating output")

        self.value = value
        self.lock_script = b'' if lock_script is None else to_bytes(lock_script)
        self.public_hash = to_bytes(public_hash)
        if isinstance(address, Address):
            self.address = address.address
            self.address_obj = address
        elif isinstance(address, HDKey):
            self.address = address.address()
            self.address_obj = address.address_obj
            public_key = address.public_byte
            script_type = script_type_default(address.witness_type, address.multisig, True)
            self.public_hash = address.hash160
        else:
            self.address = address
            self.address_obj = None
        self.public_key = to_bytes(public_key)
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        self.compressed = True
        self.k = None
        self.versionbyte = self.network.prefix_address
        self.script_type = script_type
        self.encoding = encoding
        if not self.address and self.encoding is None:
            self.encoding = 'base58'
        self.spent = spent
        self.output_n = output_n

        if self.address_obj:
            self.script_type = self.address_obj.script_type if script_type is None else script_type
            self.public_hash = self.address_obj.hash_bytes
            self.network = self.address_obj.network
            self.encoding = self.address_obj.encoding
        if self.public_key and not self.public_hash:
            k = Key(self.public_key, is_private=False, network=network)
            self.public_hash = k.hash160
        elif self.address and (not self.public_hash or not self.script_type or not self.encoding):
            address_dict = deserialize_address(self.address, self.encoding, self.network.name)
            if address_dict['script_type'] and not script_type:
                self.script_type = address_dict['script_type']
            if not self.script_type:
                raise TransactionError("Could not determine script type of address %s" % self.address)
            self.encoding = address_dict['encoding']
            network_guesses = address_dict['networks']
            if address_dict['network'] and self.network.name != address_dict['network']:
                raise TransactionError("Address %s is from %s network and transaction from %s network" %
                                       (self.address, address_dict['network'], self.network.name))
            elif self.network.name not in network_guesses:
                raise TransactionError("Network for output address %s is different from transaction network. %s not "
                                       "in %s" % (self.address, self.network.name, network_guesses))
            self.public_hash = address_dict['public_key_hash_bytes']
        if not self.encoding:
            self.encoding = 'base58'
            if self.script_type in ['p2wpkh', 'p2wsh']:
                self.encoding = 'bech32'
        if self.lock_script and not self.public_hash:
            ss = script_deserialize(self.lock_script, locking_script=True)
            self.script_type = ss['script_type']
            if self.script_type in ['p2wpkh', 'p2wsh']:
                self.encoding = 'bech32'
            if ss['hashes']:
                self.public_hash = ss['hashes'][0]
            if ss['keys']:
                self.public_key = ss['keys'][0]
                k = Key(self.public_key, is_private=False, network=network)
                self.public_hash = k.hash160
        if self.script_type is None:
            self.script_type = 'p2pkh'
            if self.encoding == 'bech32':
                self.script_type = 'p2wpkh'
        if self.public_hash and not self.address:
            self.address_obj = Address(hashed_data=self.public_hash, script_type=self.script_type,
                                       encoding=self.encoding, network=self.network)
            self.address = self.address_obj.address
            self.versionbyte = self.address_obj.prefix
        if self.lock_script == b'':
            if self.script_type == 'p2pkh':
                self.lock_script = b'\x76\xa9\x14' + self.public_hash + b'\x88\xac'
            elif self.script_type == 'p2sh':
                self.lock_script = b'\xa9\x14' + self.public_hash + b'\x87'
            elif self.script_type == 'p2wpkh':
                self.lock_script = b'\x00\x14' + self.public_hash
            elif self.script_type == 'p2wsh':
                self.lock_script = b'\x00\x20' + self.public_hash
            elif self.script_type == 'p2pk':
                if not self.public_key:
                    raise TransactionError("Public key is needed to create P2PK script for output %d" % output_n)
                self.lock_script = varstr(to_bytes(self.public_key)) + b'\xac'
            else:
                raise TransactionError("Unknown output script type %s, please provide locking script" %
                                       self.script_type)
        # if self.script_type != 'nulldata' and value < self.network.dust_amount:
        #     raise TransactionError("Output to %s must be more then dust amount %d" %
        #                            (self.address, self.network.dust_amount))

    def as_dict(self):
        """
        Get transaction output information in json format

        :return dict: Json with amount, locking script, public key, public key hash and address
        """

        return {
            'value': self.value,
            'script': to_hexstring(self.lock_script),
            'script_type': self.script_type,
            'public_key': to_hexstring(self.public_key),
            'public_hash': to_hexstring(self.public_hash),
            'address': self.address,
            'output_n': self.output_n,
            'spent': self.spent,
        }

    def __repr__(self):
        return "<Output(value=%d, address=%s, type=%s)>" % (self.value, self.address, self.script_type)


class Transaction(object):
    """
    Transaction Class
    
    Contains 1 or more Input class object with UTXO's to spent and 1 or more Output class objects with destinations.
    Besides the transaction class contains a locktime and version.
    
    Inputs and outputs can be included when creating the transaction, or can be add later with add_input and
    add_output respectively.
    
    A verify method is available to check if the transaction Inputs have valid unlocking scripts. 
    
    Each input in the transaction can be signed with the sign method provided a valid private key.
    """

    @staticmethod
    def import_raw(rawtx, network=DEFAULT_NETWORK):
        """
        Import a raw transaction and create a Transaction object
        
        Uses the _transaction_deserialize method to parse the raw transaction and then calls the init method of
        this transaction class to create the transaction object
        
        :param rawtx: Raw transaction string
        :type rawtx: bytes, str
        :param network: Network, leave empty for   default
        :type network: str, Network

        :return Transaction:
        """

        rawtx = to_bytes(rawtx)
        return _transaction_deserialize(rawtx, network=network)

    def __init__(self, inputs=None, outputs=None, locktime=0, version=1, network=DEFAULT_NETWORK,
                 fee=None, fee_per_kb=None, size=None, hash='', date=None, confirmations=None,
                 block_height=None, block_hash=None, input_total=0, output_total=0, rawtx='', status='new',
                 coinbase=False, verified=False, witness_type='legacy', flag=None):
        """
        Create a new transaction class with provided inputs and outputs. 
        
        You can also create a empty transaction and add input and outputs later.
        
        To verify and sign transactions all inputs and outputs need to be included in transaction. Any modification 
        after signing makes the transaction invalid.
        
        :param inputs: Array of Input objects. Leave empty to add later
        :type inputs: list (Input)
        :param outputs: Array of Output object. Leave empty to add later
        :type outputs: list (Output)
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param version: Version rules. Defaults to 1 in bytes 
        :type version: bytes, int
        :param network: Network, leave empty for default network
        :type network: str, Network
        :param fee: Fee in smallest denominator (ie Satoshi) for complete transaction
        :type fee: int
        :param fee_per_kb: Fee in smallest denominator per kilobyte. Specify when exact transaction size is not known.
        :type fee_per_kb: int
        :param size: Transaction size in bytes
        :type size: int
        :param date: Confirmation date of transaction
        :type date: datetime.datetime
        :param confirmations: Number of confirmations
        :type confirmations: int
        :param block_height: Block number which includes transaction
        :type block_height: int
        :param block_hash: Hash of block for this transaction
        :type block_hash: str
        :param input_total: Total value of inputs
        :type input_total: int
        :param output_total: Total value of outputs
        :type output_total: int
        :param rawtx: Raw hexstring of complete transaction
        :type rawtx: str
        :param status: Transaction status, for example: 'new', 'incomplete', 'unconfirmed', 'confirmed'
        :type status: str
        :param coinbase: Coinbase transaction or not?
        :type coinbase: bool
        :param verified: Is transaction successfully verified? Updated when verified() method is called
        :type verified: bool
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param flag: Transaction flag to indicate version, for example for SegWit
        :type flag: bytes, str

        """

        self.coinbase = coinbase
        self.inputs = []
        if inputs is not None:
            for inp in inputs:
                self.inputs.append(inp)
            if not input_total:
                input_total = sum([i.value for i in inputs])
        id_list = [i.index_n for i in self.inputs]
        if list(set(id_list)) != id_list:
            _logger.info("Identical transaction indexes (tid) found in inputs, please specify unique index. "
                         "Indexes will be automatically recreated")
            index_n = 0
            for inp in self.inputs:
                inp.index_n = index_n
                index_n += 1
        if outputs is None:
            self.outputs = []
        else:
            self.outputs = outputs
            if not output_total:
                output_total = sum([o.value for o in outputs])
        if fee is None and output_total and input_total:
            fee = input_total - output_total
            if fee < 0 or fee == 0 and not self.coinbase:
                raise TransactionError("Transaction inputs total value must be greater then total value of "
                                       "transaction outputs")

        if isinstance(version, int):
            self.version = struct.pack('>L', version)
        else:
            self.version = version
        self.locktime = locktime
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        self.flag = flag
        self.fee = fee
        self.fee_per_kb = fee_per_kb
        self.size = size
        self.vsize = size
        self.hash = hash
        self.date = date
        self.confirmations = confirmations
        self.block_height = block_height
        self.block_hash = block_hash
        self.input_total = input_total
        self.output_total = output_total
        self.rawtx = rawtx
        self.status = status
        self.verified = verified
        self.witness_type = witness_type
        self.change = 0
        if self.witness_type not in ['legacy', 'segwit']:
            raise TransactionError("Please specify a valid witness type: legacy or segwit")
        if not self.hash:
            self.hash = to_hexstring(self.signature_hash()[::-1])

    def __repr__(self):
        return "<Transaction(input_count=%d, output_count=%d, status=%s, network=%s)>" % \
               (len(self.inputs), len(self.outputs), self.status, self.network.name)

    def __str__(self):
        return self.hash

    def as_dict(self):
        """
        Return Json dictionary with transaction information: Inputs, outputs, version and locktime
        
        :return dict: 
        """

        inputs = []
        outputs = []
        for i in self.inputs:
            inputs.append(i.as_dict())
        for o in self.outputs:
            outputs.append(o.as_dict())
        return {
            'hash': self.hash,
            'date': self.date,
            'network': self.network.name,
            'witness_type': self.witness_type,
            'coinbase': self.coinbase,
            'flag': self.flag,
            'confirmations': self.confirmations,
            'block_height': self.block_height,
            'block_hash': self.block_hash,
            'fee': self.fee,
            'fee_per_kb': self.fee_per_kb,
            'inputs': inputs,
            'outputs': outputs,
            'input_total': self.input_total,
            'output_total': self.output_total,
            'version': struct.unpack('>L', self.version)[0],
            'locktime': self.locktime,
            'raw': self.raw_hex(),
            'size': self.size,
            'vsize': self.vsize,
            'verified': self.verified,
            'status': self.status
        }

    def as_json(self):
        """
        Get current key as json formatted string

        :return str:
        """
        adict = self.as_dict()
        return json.dumps(adict, indent=4)

    def info(self):
        """
        Prints transaction information to standard output
        """

        print("Transaction %s" % self.hash)
        print("Date: %s" % self.date)
        print("Network: %s" % self.network.name)
        if self.locktime and self.locktime != 0xffffffff:
            if self.locktime < 500000000:
                print("Locktime: Until block %d" % self.locktime)
            else:
                print("Locktime: Until %s UTC" % datetime.utcfromtimestamp(self.locktime))
        print("Version: %d" % struct.unpack('>L', self.version)[0])
        print("Witness type: %s" % self.witness_type)
        print("Status: %s" % self.status)
        print("Verified: %s" % self.verified)
        print("Inputs")
        replace_by_fee = False
        for ti in self.inputs:
            print("-", ti.address, ti.value, to_hexstring(ti.prev_hash), ti.output_n_int)
            validstr = "not validated"
            if ti.valid:
                validstr = "valid"
            elif ti.valid is False:
                validstr = "invalid"
            print("  %s %s; sigs: %d (%d-of-%d) %s" %
                  (ti.witness_type, ti.script_type, len(ti.signatures), ti.sigs_required or 0, len(ti.keys), validstr))
            if ti.sequence <= SEQUENCE_REPLACE_BY_FEE:
                replace_by_fee = True
            if ti.sequence <= SEQUENCE_LOCKTIME_DISABLE_FLAG:
                if ti.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print("  Relative timelock for %d seconds" % (512 * (ti.sequence - SEQUENCE_LOCKTIME_TYPE_FLAG)))
                else:
                    print("  Relative timelock for %d blocks" % ti.sequence)
            if ti.locktime_cltv:
                if ti.locktime_cltv & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print("  Check Locktime Verify (CLTV) for %d seconds" %
                          (512 * (ti.locktime_cltv - SEQUENCE_LOCKTIME_TYPE_FLAG)))
                else:
                    print("  Check Locktime Verify (CLTV) for %d blocks" % ti.locktime_cltv)
            if ti.locktime_csv:
                if ti.locktime_csv & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print("  Check Sequence Verify Timelock (CSV) for %d seconds" %
                          (512 * (ti.locktime_csv - SEQUENCE_LOCKTIME_TYPE_FLAG)))
                else:
                    print("  Check Sequence Verify Timelock (CSV) for %d blocks" % ti.locktime_csv)

        print("Outputs")
        for to in self.outputs:
            if to.script_type == 'nulldata':
                print("- NULLDATA ", to.lock_script[2:])
            else:
                spent_str = ''
                if to.spent:
                    spent_str = 'S'
                elif to.spent is False:
                    spent_str = 'U'
                print("-", to.address, to.value, to.script_type, spent_str)
        if replace_by_fee:
            print("Replace by fee: Enabled")
        print("Size: %s" % self.size)
        print("Vsize: %s" % self.vsize)
        print("Fee: %s" % self.fee)
        print("Confirmations: %s" % self.confirmations)

    def signature_hash(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Double SHA256 Hash of Transaction signature

        :param sign_id: Index of input to sign
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Legacy or Segwit witness type? Leave empty to use Transaction witness type
        :type witness_type: str

        :return bytes: Transaction signature hash
        """
        return double_sha256(self.signature(sign_id, hash_type, witness_type))

    def signature(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Serializes transaction and calculates signature for Legacy or Segwit transactions

        :param sign_id: Index of input to sign
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Legacy or Segwit witness type? Leave empty to use Transaction witness type
        :type witness_type: str

        :return bytes: Transaction signature
        """

        if witness_type is None:
            witness_type = self.witness_type
        if witness_type == 'legacy' or sign_id is None:
            return self.raw(sign_id, hash_type, 'legacy')
        elif witness_type in ['segwit', 'p2sh-segwit']:
            return self.signature_segwit(sign_id, hash_type)
        else:
            raise TransactionError("Witness_type %s not supported" % self.witness_type)

    def signature_segwit(self, sign_id, hash_type=SIGHASH_ALL):
        """
        Serialize transaction signature for segregated witness transaction

        :param sign_id: Index of input to sign
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int

        :return bytes: Segwit transaction signature
        """
        assert(self.witness_type == 'segwit')
        prevouts_serialized = b''
        sequence_serialized = b''
        outputs_serialized = b''
        hash_prevouts = b'\0' * 32
        hash_sequence = b'\0' * 32
        hash_outputs = b'\0' * 32

        for i in self.inputs:
            prevouts_serialized += i.prev_hash[::-1] + i.output_n[::-1]
            sequence_serialized += struct.pack('<L', i.sequence)
        if not hash_type & SIGHASH_ANYONECANPAY:
            hash_prevouts = double_sha256(prevouts_serialized)
            if (hash_type & 0x1f) != SIGHASH_SINGLE and (hash_type & 0x1f) != SIGHASH_NONE:
                hash_sequence = double_sha256(sequence_serialized)
        if (hash_type & 0x1f) != SIGHASH_SINGLE and (hash_type & 0x1f) != SIGHASH_NONE:
            for o in self.outputs:
                outputs_serialized += struct.pack('<Q', int(o.value))
                outputs_serialized += varstr(o.lock_script)
            hash_outputs = double_sha256(outputs_serialized)
        elif (hash_type & 0x1f) != SIGHASH_SINGLE and sign_id < len(self.outputs):
            outputs_serialized += struct.pack('<Q', int(self.outputs[sign_id].value))
            outputs_serialized += varstr(self.outputs[sign_id].lock_script)
            hash_outputs = double_sha256(outputs_serialized)

        if not self.inputs[sign_id].value:
            raise TransactionError("Need value of input %d to create transaction signature, value can not be 0" %
                                   sign_id)

        script_code = self.inputs[sign_id].redeemscript
        if not script_code:
            script_code = self.inputs[sign_id].script_code

        if not script_code or script_code == b'\0':
            raise TransactionError("Script code missing")

        ser_tx = \
            self.version[::-1] + hash_prevouts + hash_sequence + self.inputs[sign_id].prev_hash[::-1] + \
            self.inputs[sign_id].output_n[::-1] + \
            varstr(script_code) + struct.pack('<Q', int(self.inputs[sign_id].value)) + \
            struct.pack('<L', self.inputs[sign_id].sequence) + \
            hash_outputs + struct.pack('<L', self.locktime) + struct.pack('<L', hash_type)
        # print(to_hexstring(ser_tx))
        # print(sign_id, to_hexstring(script_code))
        return ser_tx

    def raw(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Serialize raw transaction
        
        Return transaction with signed inputs if signatures are available
        
        :param sign_id: Create raw transaction which can be signed by transaction with this input ID
        :type sign_id: int, None
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Serialize transaction with other witness type then default. Use to create legacy raw transaction for segwit transaction to create transaction signature ID's
        :type witness_type: str

        :return bytes:
        """

        if witness_type is None:
            witness_type = self.witness_type

        r = self.version[::-1]
        if sign_id is None and witness_type == 'segwit':
            r += b'\x00'  # marker (BIP 141)
            r += b'\x01'  # flag (BIP 141)

        r += int_to_varbyteint(len(self.inputs))
        r_witness = b''
        for i in self.inputs:
            r += i.prev_hash[::-1] + i.output_n[::-1]
            if i.witnesses and i.witness_type != 'legacy':
                r_witness += int_to_varbyteint(len(i.witnesses)) + b''.join([bytes(varstr(w)) for w in i.witnesses])
            else:
                r_witness += b'\0'
            if sign_id is None:
                r += varstr(i.unlocking_script)
            elif sign_id == i.index_n:
                r += varstr(i.unlocking_script_unsigned)
            else:
                r += b'\0'
            r += struct.pack('<L', i.sequence)

        r += int_to_varbyteint(len(self.outputs))
        for o in self.outputs:
            if o.value < 0:
                raise TransactionError("Output value < 0 not allowed")
            r += struct.pack('<Q', int(o.value))
            r += varstr(o.lock_script)

        if sign_id is None and witness_type == 'segwit':
            r += r_witness

        r += struct.pack('<L', self.locktime)
        if sign_id is not None:
            r += struct.pack('<L', hash_type)
        else:
            if not (self.size and b'' in [i.unlocking_script for i in self.inputs]):
                self.size = len(r)
        return r

    def raw_hex(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Wrapper for raw() method. Return current raw transaction hex

        :param sign_id: Create raw transaction which can be signed by transaction with this input ID
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Serialize transaction with other witness type then default. Use to create legacy raw transaction for segwit transaction to create transaction signature ID's
        :type witness_type: str

        :return hexstring: 
        """

        return to_hexstring(self.raw(sign_id, hash_type=hash_type, witness_type=witness_type))

    def verify(self):
        """
        Verify all inputs of a transaction, check if signatures match public key.
        
        Does not check if UTXO is valid or has already been spent
        
        :return bool: True if enough signatures provided and if all signatures are valid
        """

        self.verified = False
        for i in self.inputs:
            if i.script_type == 'coinbase':
                i.valid = True
                break
            if not i.signatures:
                _logger.info("No signatures found for transaction input %d" % i.index_n)
                return False
            if len(i.signatures) < i.sigs_required:
                _logger.info("Not enough signatures provided. Found %d signatures but %d needed" %
                             (len(i.signatures), i.sigs_required))
                return False
            transaction_hash = self.signature_hash(i.index_n, witness_type=i.witness_type)
            sig_id = 0
            key_n = 0
            for key in i.keys:
                if sig_id > i.sigs_required-1:
                    break
                if sig_id >= len(i.signatures):
                    _logger.info("No valid signatures found")
                    return False
                if not transaction_hash:
                    _logger.info("Need at least 1 key to create segwit transaction signature")
                    return False
                key_n += 1
                if verify(transaction_hash, i.signatures[sig_id], key):
                    sig_id += 1
                    i.valid = True
                else:
                    i.valid = False
            if sig_id < i.sigs_required:
                _logger.info("Not enough valid signatures provided for input %d. Found %d signatures but %d needed" %
                             (i.index_n, sig_id, i.sigs_required))
                return False
        self.verified = True
        return True

    def sign(self, keys=None, tid=None, multisig_key_n=None, hash_type=SIGHASH_ALL, _fail_on_unknown_key=True):
        """
        Sign the transaction input with provided private key
        
        :param keys: A private key or list of private keys
        :type keys: HDKey, Key, bytes, list
        :param tid: Index of transaction input
        :type tid: int
        :param multisig_key_n: Index number of key for multisig input for segwit transactions. Leave empty if not known. If not specified all possibilities will be checked
        :type multisig_key_n: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param _fail_on_unknown_key: Method fails if public key from signature is not found in public key list
        :type _fail_on_unknown_key: bool

        :return None:
        """

        if tid is None:
            tids = range(len(self.inputs))
        else:
            tids = [tid]

        if keys is None:
            keys = []
        elif not isinstance(keys, list):
            keys = [keys]

        for tid in tids:
            n_signs = 0
            tid_keys = [k if isinstance(k, (HDKey, Key)) else Key(k, compressed=self.inputs[tid].compressed)
                        for k in keys]
            for k in self.inputs[tid].keys:
                if k.is_private and k not in tid_keys:
                    tid_keys.append(k)
            # If input does not contain any keys, try using provided keys
            if not self.inputs[tid].keys:
                self.inputs[tid].keys = tid_keys
                self.inputs[tid].update_scripts(hash_type=hash_type)
            if self.inputs[tid].script_type == 'coinbase':
                raise TransactionError("Can not sign coinbase transactions")
            pub_key_list = [k.public_byte for k in self.inputs[tid].keys]
            n_total_sigs = len(self.inputs[tid].keys)
            sig_domain = [''] * n_total_sigs

            tx_hash = self.signature_hash(tid, witness_type=self.inputs[tid].witness_type)
            for key in tid_keys:
                # Check if signature signs known key and is not already in list
                if key.public_byte not in pub_key_list:
                    if _fail_on_unknown_key:
                        raise TransactionError("This key does not sign any known key: %s" % key.public_hex)
                    else:
                        continue
                if key in [x.public_key for x in self.inputs[tid].signatures]:
                    _logger.info("Key %s already signed" % key.public_hex)
                    break

                if not key.private_byte:
                    raise TransactionError("Please provide a valid private key to sign the transaction")
                sig = sign(tx_hash, key)
                newsig_pos = pub_key_list.index(key.public_byte)
                sig_domain[newsig_pos] = sig
                n_signs += 1

            if not n_signs:
                break

            # Add already known signatures on correct position
            n_sigs_to_insert = len(self.inputs[tid].signatures)
            for sig in self.inputs[tid].signatures:
                if not sig.public_key:
                    break
                newsig_pos = pub_key_list.index(sig.public_key.public_byte)
                if sig_domain[newsig_pos] == '':
                    sig_domain[newsig_pos] = sig
                    n_sigs_to_insert -= 1
            if n_sigs_to_insert:
                for sig in self.inputs[tid].signatures:
                    free_positions = [i for i, s in enumerate(sig_domain) if s == '']
                    for pos in free_positions:
                        sig_domain[pos] = sig
                        n_sigs_to_insert -= 1
                        break
            if n_sigs_to_insert:
                _logger.info("Some signatures are replaced with the signatures of the provided keys")
            self.inputs[tid].signatures = [s for s in sig_domain if s != '']

        self.inputs[tid].update_scripts(hash_type)

    def add_input(self, prev_hash, output_n, keys=None, signatures=None, public_hash=b'', unlocking_script=b'',
                  unlocking_script_unsigned=None, script_type=None, address='',
                  sequence=0xffffffff, compressed=True, sigs_required=None, sort=False, index_n=None,
                  value=None, double_spend=False, locktime_cltv=None, locktime_csv=None,
                  key_path='', witness_type=None, encoding=None):
        """
        Add input to this transaction
        
        Wrapper for append method of Input class.

        :param prev_hash: Transaction hash of the UTXO (previous output) which will be spent.
        :type prev_hash: bytes, hexstring
        :param output_n: Output number in previous transaction.
        :type output_n: bytes, int
        :param keys: Public keys can be provided to construct an Unlocking script. Optional
        :type keys: bytes, str
        :param signatures: Add signatures to input if already known
        :type signatures: bytes, str
        :param public_hash: Specify public hash from key or redeemscript if key is not available
        :type public_hash: bytes, str
        :param unlocking_script: Unlocking script (scriptSig) to prove ownership. Optional
        :type unlocking_script: bytes, hexstring
        :param unlocking_script_unsigned: TODO: find better name...
        :type unlocking_script_unsigned: bytes, str
        :param script_type: Type of unlocking script used, i.e. p2pkh or p2sh_multisig. Default is p2pkh
        :type script_type: str
        :param address: Specify address of input if known, default is to derive from key or scripts
        :type address: str, Address
        :param sequence: Sequence part of input, used for timelocked transactions
        :type sequence: int, bytes
        :param compressed: Use compressed or uncompressed public keys. Default is compressed
        :type compressed: bool
        :param sigs_required: Number of signatures required for a p2sh_multisig unlocking script
        :param sigs_required: int
        :param sort: Sort public keys according to BIP0045 standard. Default is False to avoid unexpected change of key order.
        :type sort: boolean
        :param index_n: Index number of position in transaction, leave empty to add input to end of inputs list
        :type index_n: int
        :param value: Value of input
        :type value: int
        :param double_spend: True if double spend is detected, depends on which service provider is selected
        :type double_spend: bool
        :param locktime_cltv: Check Lock Time Verify value. Script level absolute time lock for this input
        :type locktime_cltv: int
        :param locktime_csv: Check Sequency Verify value.
        :type locktime_csv: int
        :param key_path: Key path of input key as BIP32 string or list
        :type key_path: str, list
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty to derive from script or script type
        :type encoding: str

        :return int: Transaction index number (index_n)
        """

        if index_n is None:
            index_n = len(self.inputs)
        sequence_int = sequence
        if isinstance(sequence, bytes):
            sequence_int = struct.unpack('<L', sequence)[0]
        if self.version == b'\x00\x00\x00\x01' and 0 < sequence_int < SEQUENCE_LOCKTIME_DISABLE_FLAG:
            self.version = b'\x00\x00\x00\x02'
        self.inputs.append(
            Input(prev_hash=prev_hash, output_n=output_n, keys=keys, signatures=signatures, public_hash=public_hash,
                  unlocking_script=unlocking_script, unlocking_script_unsigned=unlocking_script_unsigned,
                  script_type=script_type, address=address, sequence=sequence, compressed=compressed,
                  sigs_required=sigs_required, sort=sort, index_n=index_n, value=value, double_spend=double_spend,
                  locktime_cltv=locktime_cltv, locktime_csv=locktime_csv, key_path=key_path, witness_type=witness_type,
                  encoding=encoding, network=self.network.name))
        return index_n

    def add_output(self, value, address='', public_hash=b'', public_key=b'', lock_script=b'', spent=False,
                   output_n=None, encoding=None):
        """
        Add an output to this transaction
        
        Wrapper for the append method of the Output class.
        
        :param value: Value of output in smallest denominator of currency, for example satoshi's for bitcoins
        :type value: int
        :param address: Destination address of output. Leave empty to derive from other attributes you provide.
        :type address: str, Address
        :param public_hash: Hash of public key or script
        :type public_hash: bytes, str
        :param public_key: Destination public key
        :type public_key: bytes, str
        :param lock_script: Locking script of output. If not provided a default unlocking script will be provided with a public key hash.
        :type lock_script: bytes, str
        :param spent: Has output been spent in new transaction?
        :type spent: bool, None
        :param output_n: Index number of output in transaction
        :type output_n: int
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty for to derive from script or script type
        :type encoding: str

        :return int: Transaction output number (output_n)
        """

        lock_script = to_bytes(lock_script)
        if output_n is None:
            output_n = len(self.outputs)
        if not float(value).is_integer():
            raise TransactionError("Output must be of type integer and contain no decimals")
        if lock_script.startswith(b'\x6a'):
            if value != 0:
                raise TransactionError("Output value for OP_RETURN script must be 0")
        # elif value < self.network.dust_amount and strict:
        #     raise TransactionError("Output must be more then dust amount %d" % self.network.dust_amount)
        self.outputs.append(Output(value=int(value), address=address, public_hash=public_hash,
                                   public_key=public_key, lock_script=lock_script, spent=spent, output_n=output_n,
                                   encoding=encoding, network=self.network.name))
        return output_n

    def estimate_size(self, add_change_output=False):
        """
        Get estimated vsize in for current transaction based on transaction type and number of inputs and outputs.

        For old-style legacy transaction the vsize is the length of the transaction. In segwit transaction the
        witness data has less weight. The formula used is: math.ceil(((est_size-witness_size) * 3 + est_size) / 4)

        :param add_change_output: Assume an extra change output will be created but has not been created yet.
        :type add_change_output: bool

        :return int: Estimated transaction size
        """

        # if self.input_total and self.output_total + self.fee == self.input_total:
        #     add_change_output = False
        est_size = 10
        witness_size = 2
        if self.witness_type != 'legacy':
            est_size += 2
        for inp in self.inputs:
            est_size += 40
            scr_size = 0
            if inp.witness_type != 'legacy':
                est_size += 1
            if inp.unlocking_script and len(inp.signatures) >= inp.sigs_required:
                scr_size += len(varstr(inp.unlocking_script))
                if inp.witness_type == 'p2sh-segwit':
                    scr_size += sum([1 + len(w) for w in inp.witnesses])
            else:
                if inp.script_type == 'sig_pubkey':
                    scr_size += 107
                    if not inp.compressed:
                        scr_size += 33
                    if inp.witness_type == 'p2sh-segwit':
                        scr_size += 24
                # elif inp.script_type in ['p2sh_multisig', 'p2sh_p2wpkh', 'p2sh_p2wsh']:
                elif inp.script_type == 'p2sh_multisig':
                    scr_size += 9 + (len(inp.keys) * 34) + (inp.sigs_required * 72)
                    if inp.witness_type == 'p2sh-segwit':
                        scr_size += 17 * inp.sigs_required
                elif inp.script_type == 'signature':
                    scr_size += 9 + 72
                else:
                    raise TransactionError("Unknown input script type %s cannot estimate transaction size" %
                                           inp.script_type)
            est_size += scr_size
            witness_size += scr_size
        if not self.inputs:
            est_size += 147  # If nothing is known assume 1 p2sh/p2pkh input
        for outp in self.outputs:
            est_size += 8
            if outp.lock_script:
                est_size += len(varstr(outp.lock_script))
            else:
                raise TransactionError("Need locking script for output %d to estimate size" % outp.output_n)
        if add_change_output:
            is_multisig = True if self.inputs and self.inputs[0].script_type == 'p2sh_multisig' else False
            est_size += 8
            if not self.inputs or self.inputs[0].witness_type == 'legacy':
                est_size += 24 if is_multisig else 26
            elif self.inputs[0].witness_type == 'p2sh-segwit':
                est_size += 24
            else:
                est_size += 33 if is_multisig else 23
        self.size = est_size
        self.vsize = est_size
        if self.witness_type == 'legacy':
            return est_size
        else:
            self.vsize = math.ceil(((est_size-witness_size) * 3 + est_size) / 4)
            return self.vsize

    def calculate_fee(self):
        """
        Get fee for this transaction in smallest denominator (i.e. Satoshi) based on its size and the
        transaction.fee_per_kb value

        :return int: Estimated transaction fee
        """

        if not self.fee_per_kb:
            raise TransactionError("Cannot calculate transaction fees: transaction.fee_per_kb is not set")
        return int(self.estimate_size()/1024.0 * self.fee_per_kb)

    def update_totals(self):
        """
        Update input_total, output_total and fee according to inputs and outputs of this transaction

        :return int:
        """

        self.input_total = sum([i.value for i in self.inputs if i.value])
        self.output_total = sum([o.value for o in self.outputs if o.value])
        # self.fee = 0
        if self.input_total:
            self.fee = self.input_total - self.output_total
