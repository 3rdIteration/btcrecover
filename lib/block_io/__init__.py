from Crypto.Cipher import AES
import base64
from lib.cashaddress import base58
#import requests

from hashlib import sha256, pbkdf2_hmac

from .bitcoinutils_patches import *

class BlockIoInvalidResponseError(Exception):
    """Thrown when we receive an unexpected/unparseable response from Block.io"""

class BlockIoUnknownError(Exception):
    """Thrown when response status codes are outside of 200-299, 419-420, 500-599."""

class BlockIoAPIThrottleError(Exception):
    """Thrown when API call gets throttled at Block.io."""

class BlockIoAPIInternalError(Exception):
    """Thrown on 500-599 errors."""

class BlockIoAPIError(Exception):
    """Thrown when block.io API call fails."""

class IncorrectDecryptionPasswordError(Exception):
    """Thrown when incorrect decryption password supplied."""

    def set_raw_data(self, data):
        self.raw_data = data

    def get_raw_data(self):
        return self.raw_data
    

class BlockIo(object):

    class Key:
        # wrapper around bitcoinutils.keys.PrivateKey
        def __init__(self, privkey, pubkey = None):
            # we will always use compressed public keys
            self.private_key = bitcoinutils.keys.PrivateKey(secret_exponent=int(hexlify(privkey),16))
            self.public_key = self.private_key.get_public_key()

        @staticmethod
        def generate():
            return BlockIo.Key(bitcoinutils.keys.PrivateKey().to_bytes(), None)

        @staticmethod
        def from_privkey_hex(privkey):
            return BlockIo.Key(unhexlify(privkey.rjust(64, "0")), None)
        
        def sign(self, data_to_sign):
            # use the sign_input method from bitcoinutils.keys.PrivateKey
            der_sig = self.private_key._sign_input(data_to_sign, bitcoinutils.constants.SIGHASH_ALL)
            return unhexlify(der_sig)

        def sign_hex(self, hex_data):
            return hexlify(self.sign(unhexlify(hex_data)))

        def privkey_hex(self):
            return hexlify(self.private_key.to_bytes())
        
        def pubkey_hex(self):
            return self.public_key.to_hex(compressed=True).encode('utf-8')

        @staticmethod
        def from_passphrase(passphrase):
            # use the sha256 of the given passphrase as the private key
            private_key = sha256(passphrase).digest()
            return BlockIo.Key(private_key)

        @staticmethod
        def from_wif(privkey):
            # extract the secret exponent from the given coin-formatted private key
            private_key = ""

            try:
                extended_key_bytes = base58.b58decode_check(privkey)
            except ValueError as e:
                # Invalid checksum!
                raise Exception("Invalid Private Key provided. Must be in Wallet Import Format.")

            # is this a compressed WIF or not?
            is_compressed = len(hexlify(extended_key_bytes)) == 68 and hexlify(extended_key_bytes)[-2:].decode("utf-8") == "01"

            if is_compressed == False:
                raise Exception("WIF must always be compressed.")
        
            # Drop the network bytes
            extended_key_bytes = extended_key_bytes[1:]

            private_key = extended_key_bytes

            if (len(private_key) == 33):
                private_key = extended_key_bytes[:-1]

            return BlockIo.Key(private_key, None)

    class Helper:

        @staticmethod
        def pinToAesKey(pin, salt = "", iterations = 2048, hashfn = sha256, phase1_key_length = 16, phase2_key_length = 32):

            ret = pbkdf2_hmac("sha256", pin.encode(), salt.encode(), int(iterations/2),phase1_key_length)
            ret = pbkdf2_hmac("sha256", hexlify(ret), salt.encode(), int(iterations / 2), phase2_key_length)
            return hexlify(ret) # the encryption key

        @staticmethod
        def dynamicExtractKey(user_key, pin):
            # uses the algorithm specified in the user_key object
            # if no algorithm specified, uses the following default (legacy)
            
            algorithm = {
                "pbkdf2_salt": "",
                "pbkdf2_iterations": 2048,
                "pbkdf2_hash_function": "SHA256",
                "pbkdf2_phase1_key_length": 16,
                "pbkdf2_phase2_key_length": 32,
                "aes_iv": None,
                "aes_cipher": "AES-256-ECB",
                "aes_auth_tag": None,
                "aes_auth_data": None
            }

            if 'algorithm' in user_key:
                algorithm = user_key['algorithm']

            if algorithm['pbkdf2_hash_function'] != "SHA256":
                raise Exception("Unknown hash function specified. Are you using current version of this library?")
            
            aes_key = BlockIo.Helper.pinToAesKey(pin, algorithm['pbkdf2_salt'], algorithm['pbkdf2_iterations'],
                                  sha256, algorithm['pbkdf2_phase1_key_length'], algorithm['pbkdf2_phase2_key_length'])

            decrypted = BlockIo.Helper.decrypt(user_key['encrypted_passphrase'], aes_key,
                                               algorithm['aes_iv'], algorithm['aes_cipher'], algorithm['aes_auth_tag'])

            return BlockIo.Key.from_passphrase(unhexlify(decrypted))
        
        @staticmethod
        def extractKey(encrypted_data, enc_key_hex):
            # encryption key is in hex
            decrypted = BlockIo.Helper.decrypt(encrypted_data, enc_key_hex)
            return BlockIo.Key.from_passphrase(unhexlify(decrypted))

        @staticmethod
        def encrypt(data, key, iv = None, cipher_type = "AES-256-ECB", auth_data = None):
            # key in hex, data as string
            # returns ciphertext in base64

            key = unhexlify(key) # get bytes

            BS = 16
            pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
            unpad = lambda s : s[0:-s[-1]]

            obj = None

            if cipher_type == "AES-256-ECB":
                obj = AES.new(key, AES.MODE_ECB)
            elif cipher_type == "AES-256-CBC":
                obj = AES.new(key, AES.MODE_CBC, unhexlify(iv))
            elif cipher_type == "AES-256-GCM":
                obj = AES.new(key, AES.MODE_GCM, unhexlify(iv))
            else:
                raise Exception("Unsupported cipher", cipher_type)

            response = {"aes_iv": iv, "aes_cipher_text": None, "aes_auth_tag": None, "aes_auth_data": None, "aes_cipher": cipher_type}

            if cipher_type != "AES-256-GCM":
                response["aes_cipher_text"] = base64.b64encode(obj.encrypt(pad(data).encode('latin-1')))
            else:
                # AES-256-GCM
                # no padding for data
                ciphertext = obj.encrypt(data.encode('latin-1'))
                response["aes_cipher_text"] = base64.b64encode(ciphertext)
                response["aes_auth_tag"] = hexlify(obj.digest())
                
            return response

        @staticmethod
        def decrypt(b64data, key, iv = None, cipher_type = "AES-256-ECB", auth_tag = None):
            # key in hex, b64data as base64 string
            # returns utf-8 string

            message = None

            try:

                key = unhexlify(key) # get bytes
                
                BS = 16
                pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
                unpad = lambda s : s[0:-s[-1]]
                
                data = base64.b64decode(b64data) # decode from base64
                
                obj = None
                
                if cipher_type == "AES-256-ECB":
                    obj = AES.new(key, AES.MODE_ECB)
                elif cipher_type == "AES-256-CBC":
                    obj = AES.new(key, AES.MODE_CBC, unhexlify(iv))
                elif cipher_type == "AES-256-GCM":
                    obj = AES.new(key, AES.MODE_GCM, unhexlify(iv))
                else:
                    raise Exception("Unsupported cipher", cipher_type)
            
                message = None

                if cipher_type != "AES-256-GCM":
                    message = unpad(obj.decrypt(data))
                else:
                    # AES-256-GCM
                    # Auth tag must be exactly 16 bytes
                    if (len(auth_tag) != 32):
                        raise Exception("Auth tag must be 16 bytes exactly.")
                    message = obj.decrypt_and_verify(data, unhexlify(auth_tag))
                
            except:
                # error decrypting? must be an invalid secret pin
                raise IncorrectDecryptionPasswordError('Invalid Secret PIN provided.')

            return message

        @staticmethod
        def compress_pubkey(pubkey):
            x = pubkey[:32]
            y = pubkey[33:64]
            y_int = 0;
            for c in bytes(y):
                y_int = 256 * y_int + c
            return bytes((2+(y_int % 2),)) + x

    def __init__(self, api_key, pin, version = 2):
        # initiate the object
        self.api_key = api_key
        self.pin = pin
        self.version = version
        self.clientVersion = VERSION
        self.encryption_key = None
        self.base_url = 'https://block.io/api/v'+str(version)+'/API_CALL/?api_key='+api_key
        self.sweep_calls = ['prepare_sweep_transaction']
        self.request_headers = {'Accept': 'application/json', 'User-Agent': 'python:block_io:'+self.clientVersion}
        self.private_keys = dict()
        
    def __getattr__(self, attr, *args, **kwargs):

        def hook(*args, **kwargs):
            return self.api_call(attr, **kwargs)

        def sweep_hook(*args, **kwargs):
            return self.internal_prepare_sweep_transaction(attr, **kwargs)

        if any(attr in s for s in self.sweep_calls):
            return sweep_hook
        else:
            return hook


    def internal_prepare_sweep_transaction(self, method, **kwargs):
        # sweep call meta

        key = self.Key.from_wif(kwargs['private_key'])

        del kwargs['private_key'] # remove the key, we're not going to pass it on
        kwargs['public_key'] = key.pubkey_hex().decode("utf-8")

        # save the key for later use
        self.private_keys[key.pubkey_hex().decode('utf-8')] = PrivateKey(secret_exponent=int(key.privkey_hex().decode('utf-8'),16))
        
        response = self.api_call(method, **kwargs)

        return response

    def create_redeem_script(self, required_signatures, public_keys):
        # returns the redeem script given the ordered public_keys and required signatures

        script_elements = []
        script_elements.append('OP_' + str(required_signatures))

        for public_key in public_keys:
            script_elements.append(public_key)

        script_elements.append('OP_' + str(len(public_keys)))
        script_elements.append('OP_CHECKMULTISIG')

        return Script(script_elements)

    def summarize_prepared_transaction(self, data):
        # returns summary of the prepared data
        # includes network fee, blockio fee, total amount to send

        inputs = data['data']['inputs']
        outputs = data['data']['outputs']

        network_fee = Decimal(0)
        blockio_fee = Decimal(0)
        change_amount = Decimal(0)
        input_sum = Decimal(0)
        output_sum = Decimal(0)

        # get the sum of coins being spent
        for cur_input in inputs:
            input_sum += Decimal(cur_input['input_value'])

        # populate various categories of outputs
        for cur_output in outputs:
            if cur_output['output_category'] == 'blockio-fee':
                blockio_fee += Decimal(cur_output['output_value'])
            elif cur_output['output_category'] == 'change':
                change_amount += Decimal(cur_output['output_value'])
            else:
                # user-specified
                output_sum += Decimal(cur_output['output_value'])

        # summarize the data
        return {"network": data['data']['network'],
                "network_fee": format(input_sum - output_sum - change_amount - blockio_fee, '.8f'),
                "blockio_fee": format(blockio_fee, '.8f'),
                "total_amount_to_send": format(output_sum, '.8f')}
    
    def create_and_sign_transaction(self, prepare_data, keys = []):
        # creates the specified transaction with the inputs and outputs
        # signs what we can and returns payload and signatures left to append, if any

        # set the appropriate network first
        bitcoinutils_patches.bitcoinutils_setup(prepare_data['data']['network'])
        
        # save the provided keys so we can use them below
        for cur_key_hex in keys:
            cur_key = PrivateKey(secret_exponent=int(cur_key_hex,16))
            self.private_keys[cur_key.get_public_key().to_hex(compressed=True)] = cur_key

        if self.pin is None and 'user_key' in prepare_data['data'] and prepare_data['data']['user_key']['public_key'] not in self.private_keys:
            raise BlockIoUnknownError("No PIN provided to decrypt signer private key.")
        
        # decrypt the signer private key if we can
        if self.pin is not None and 'user_key' in prepare_data['data'] and prepare_data['data']['user_key']['public_key'] not in self.private_keys:

            key = self.Helper.dynamicExtractKey(prepare_data['data']['user_key'], self.pin)

            if (key.pubkey_hex().decode('utf-8') != prepare_data['data']['user_key']['public_key']):
                raise Exception("Expected pubkey=",prepare_data['data']['user_key']['public_key'],"but got pubkey=",key.pubkey_hex(),". Invalid PIN provided.")
            
            self.private_keys[key.pubkey_hex().decode('utf-8')] = PrivateKey(secret_exponent=int(key.privkey_hex().decode('utf-8'),16))

        # we can create the transaction now
        inputs = prepare_data['data']['inputs']
        outputs = prepare_data['data']['outputs']

        # create a dictionary for these input addresses
        input_address_data = prepare_data['data']['input_address_data']
        address_data = dict()

        for input_address in input_address_data:
            address_data[input_address['address']] = input_address
            
        has_segwit_inputs = False
        
        # create the transaction

        # inputs
        tx_inputs = []

        for cur_input in inputs:
            tx_input = TxInput(cur_input['previous_txid'], cur_input['previous_output_index'])
            cur_address_data = address_data[cur_input['spending_address']]
            cur_address_type = cur_address_data['address_type']

            # if this transaction has any segwit inputs, set has_segwit_inputs
            if (cur_address_type == 'P2WSH-over-P2SH' or
                cur_address_type == 'P2WPKH-over-P2SH' or
                cur_address_type == 'P2WPKH' or
                cur_address_type == 'WITNESS_V0'):
                has_segwit_inputs = True

            tx_inputs.append(tx_input)

        # outputs
        tx_outputs = []
        
        for cur_output in outputs:
            tx_output = TxOutput(bitcoinutils.utils.to_satoshis(cur_output['output_value']), get_output_script(cur_output['receiving_address']))
            tx_outputs.append(tx_output)

        tx = Transaction(tx_inputs, tx_outputs, has_segwit=has_segwit_inputs)

        # if we have expected unsigned txid, make sure this library's serialized the unsigned transaction properly
        if 'expected_unsigned_txid' in prepare_data['data'] and prepare_data['data']['expected_unsigned_txid'] is not None:
            if prepare_data['data']['expected_unsigned_txid'] != tx.get_txid():
                raise Exception("Expected unsigned transaction ID mismatch. Please report this error to support@block.io.")
                
        # start signing inputs
        signatures = []
        signatures_dict = dict() # makes our job easier for when we need to serialize the transaction with signatures
        tx_fully_signed = True # assume tx will be fully signed
        
        for cur_input in inputs:
            cur_address_data = address_data[cur_input['spending_address']]
            cur_public_keys = cur_address_data['public_keys']
            cur_address_type = cur_address_data['address_type']
            cur_required_signatures = cur_address_data['required_signatures']
            cur_signatures = dict()
            
            if cur_address_type == 'P2SH' or cur_address_type == 'P2WSH-over-P2SH' or cur_address_type == 'WITNESS_V0':
                # P2SH, or P2WSH-over-P2SH, or P2WSH (WITNESS_V0) input

                redeem_script = self.create_redeem_script(cur_required_signatures, cur_public_keys)
                
                # sign for each public key, if we can
                for public_key in cur_public_keys:
                    if (public_key in self.private_keys):
                        if (cur_address_type == 'P2SH'):
                            # P2SH address
                            cur_signatures[public_key] = self.private_keys[public_key].sign_input(tx, cur_input['input_index'], redeem_script)
                        else:
                            # witness input
                            cur_signatures[public_key] = self.private_keys[public_key].sign_segwit_input(tx,
                                                                                                         cur_input['input_index'],
                                                                                                         redeem_script,
                                                                                                         bitcoinutils.utils.to_satoshis(cur_input['input_value']))
                            
                if (len(cur_signatures) < cur_required_signatures):
                    # transaction is going to be missing signatures
                    # we'll need to use Block.io's signatures as well
                    tx_fully_signed = False

            elif cur_address_type == 'P2PKH' or cur_address_type == 'P2WPKH-over-P2SH' or cur_address_type == 'P2WPKH':
                pkh_script = get_output_script(PublicKey(cur_public_keys[0]).get_address().to_string())

                if (cur_public_keys[0] in self.private_keys):
                    if cur_address_type == 'P2PKH':
                        # P2PKH address
                        cur_signatures[cur_public_keys[0]] = self.private_keys[cur_public_keys[0]].sign_input(tx, cur_input['input_index'], pkh_script)
                    else:
                        # witness input
                        cur_signatures[cur_public_keys[0]] = self.private_keys[cur_public_keys[0]].sign_segwit_input(tx,
                                                                                                                     cur_input['input_index'],
                                                                                                                     pkh_script,
                                                                                                                     bitcoinutils.utils.to_satoshis(cur_input['input_value']))

            else:
                raise Exception("Unrecognized address type:", cur_address_type)

            # signatures done here for this input
            # append signatures to our signatures array
            for public_key in cur_signatures:
                signatures.append({'public_key': public_key, 'signature': cur_signatures[public_key].decode('utf-8'), 'input_index': cur_input['input_index']})

                if (str(cur_input['input_index']) not in signatures_dict):
                    signatures_dict[str(cur_input['input_index'])] = dict()

                signatures_dict[str(cur_input['input_index'])][public_key] = cur_signatures[public_key]

        # this will be our response object
        response = {"tx_type": prepare_data['data']['tx_type'], "tx_hex": None, "signatures": None}
        
        if tx_fully_signed == True:
            # if the transaction is fully signed, we will just serialize it with all the signatures

            for cur_input in inputs:
                # for each input, prepare the script_sig and/or witnesses
                cur_address_data = address_data[cur_input['spending_address']]
                cur_public_keys = cur_address_data['public_keys']
                cur_address_type = cur_address_data['address_type']
                cur_input_index = cur_input['input_index']
                
                if cur_address_data['required_signatures'] > 1:
                    # P2SH, P2WSH-over-P2SH, or P2WSH (WITNESS_V0) input

                    # we will need the redeem script now
                    redeem_script = self.create_redeem_script(cur_address_data['required_signatures'], cur_public_keys)
                    script_elements = ["OP_0"] # the blank push

                    signatures_left = cur_address_data['required_signatures'] + 0
                    
                    for public_key in cur_public_keys:
                        if (signatures_left > 0):
                            # append signatures only if we haven't reached the required number of signatures yet
                            if public_key in signatures_dict[str(cur_input_index)]:
                                script_elements.append(signature_with_sighash(signatures_dict[str(cur_input_index)][public_key]))
                                signatures_left = signatures_left - 1

                    if (signatures_left > 0):
                        raise BlockIoUnknownError("Signatures left should be zero, but signatures_left=", signatures_left)

                    script_elements.append(redeem_script.to_hex())

                    script_sig = Script(script_elements)

                    if cur_address_type == "P2SH":
                        tx_inputs[cur_input_index].script_sig = script_sig
                    else:
                        # P2WSH-over-P2SH and P2WSH (WITNESS_V0)
                        tx.witnesses.append(script_sig)

                    if cur_address_type == "P2WSH-over-P2SH":
                        # needs script_sig set as well
                        tx_inputs[cur_input_index].script_sig = Script([get_output_script(P2wshAddress.from_script(redeem_script).to_string()).to_hex()])
                        
                else:
                    # P2PKH, P2WPKH-over-P2SH, or P2WPKH
                    cur_signature = signatures_dict[str(cur_input_index)][cur_public_keys[0]]
                    script_sig = Script([signature_with_sighash(cur_signature), cur_public_keys[0]])

                    if cur_address_type == "P2PKH":
                        tx_inputs[cur_input_index].script_sig = script_sig
                    else:
                        # P2WPKH-over-P2SH and P2WPKH
                        tx.witnesses.append(script_sig)

                    if cur_address_type == "P2WPKH-over-P2SH":
                        # needs script_sig set as well
                        tx_inputs[cur_input_index].script_sig = Script([get_output_script(PublicKey(cur_public_keys[0]).get_segwit_address().to_string()).to_hex()])


        if (tx_fully_signed == False):
            # we have signatures to append
            response["signatures"] = signatures
            
        response["tx_hex"] = tx.serialize() # the payload

        # remove all private keys from self
        self.private_keys = dict()
        
        return response

    def api_call(self, method, **kwargs):
        # the actual API call

        # http parameters
        payload = {}

        if self.api_key is not None:
            payload["api_key"] = self.api_key

        payload.update(kwargs)

        # update the parameters with the API key
        session = requests.session()
        response = session.post(self.base_url.replace('API_CALL',method), json = payload, headers = self.request_headers)
        status_code = response.status_code
        
        try:
            response = response.json() # convert response to JSON
        except:
            response = {}

        session.close() # we're done with it, let's close it

        if not ('status' in response.keys()):
            # unexpected response
            raise BlockIoInvalidResponseError("Failed, invalid response received from Block.io, method %s" % method)
        elif ('status' in response.keys()) and (response['status'] == 'fail'):

            # give the user the raw response as well in the exception object
            api_error = BlockIoAPIError(response['data']['error_message'])
            api_error.set_raw_data(response)

            raise api_error

        elif 500 <= status_code <= 599:
            # using the status_code since a JSON response was not provided
            raise BlockIoAPIInternalError("API call to Block.io failed externally, method %s" % method)
        elif 419 <= status_code <= 420:
            # using the status_code since a JSON response was not provided
            raise BlockIoAPIThrottleError("API call got throttled by rate limits at Block.io, method %s" % method)
        elif not (200 <= status_code <= 299):
            # using the status_code since a JSON response was not provided
            raise BlockIoUnknownError("Unknown error occurred when querying Block.io, method %s" % method)

        return response
