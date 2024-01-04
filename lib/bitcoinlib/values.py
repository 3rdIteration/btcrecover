# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    VALUE class - representing cryptocurrency values
#    © 2022 October - 1200 Web Development <http://1200wd.com/>
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

from bitcoinlib.networks import *
from bitcoinlib.config.config import NETWORK_DENOMINATORS


def value_to_satoshi(value, network=None):
    """
    Convert Value object or value string to the smallest denominator amount as integer

    :param value: Value object, value string as accepted by Value class or numeric value amount
    :type value: str, int, float, Value
    :param network: Specify network to validate value string
    :type network: str, Network

    :return int:
    """
    if isinstance(value, str):
        value = Value(value)
    if isinstance(value, Value):
        if network and value.network != network:
            raise ValueError("Value uses different network (%s) then supplied network: %s" % (value.network.name, network))
        value = value.value_sat
    return value


class Value:
    """
    Class to represent and convert cryptocurrency values
    """

    @classmethod
    def from_satoshi(cls, value, denominator=None, network=DEFAULT_NETWORK):
        """
        Initialize Value class with the smallest denominator as input. Such as represented in script and transactions
        cryptocurrency values.

        :param value: Amount of Satoshi's / smallest denominator for this network
        :type value: int
        :param denominator: Denominator as integer or string. Such as 0.001 or m for milli, 1000 or k for kilo, etc. See NETWORK_DENOMINATORS for list of available denominator symbols.
        :type denominator: int, float, str
        :param network: Specify network if not supplied already in the value string
        :type network: str, Network

        :return Value:
        """
        if not isinstance(network, Network):
            network = Network(network)
        if denominator is None:
            denominator = network.denominator
        else:
            if isinstance(denominator, str):
                dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
                if dens:
                    denominator = dens[0]
            value = value * (network.denominator / denominator)
        return cls(value or 0, denominator, network)

    def __init__(self, value, denominator=None, network=DEFAULT_NETWORK):
        """
        Create a new Value class. Specify value as integer, float or string. If a string is provided
        the amount, denominator and currency will be extracted if provided

        Examples: Initialize value class
        >>> Value(10)
        Value(value=10.00000000000000, denominator=1.00000000, network='bitcoin')

        >>> Value('15 mBTC')
        Value(value=0.01500000000000, denominator=0.00100000, network='bitcoin')

        >>> Value('10 sat')
        Value(value=0.00000010000000, denominator=0.00000001, network='bitcoin')

        >>> Value('1 doge')
        Value(value=1.00000000000000, denominator=1.00000000, network='dogecoin')

        >>> Value(500, 'm')
        Value(value=0.50000000000000, denominator=0.00100000, network='bitcoin')

        >>> Value(500, 0.001)
        Value(value=0.50000000000000, denominator=0.00100000, network='bitcoin')

        All frequently used arithmetic, comparision and logical operators can be used on the Value object. So you can compare Value object, add them together, divide or multiply them, etc.

        Values need to use the same network / currency if you work with multiple Value objects. I.e. Value('1 BTC') + Value('1 LTC') raises an error.

        # Examples: Value operators
        >>> Value('50000 sat') == Value('5000 fin')  # 1 Satoshi equals 10 Finney, see https://en.bitcoin.it/wiki/Units
        True

        >>> Value('1 btc') > Value('2 btc')
        False

        >>> Value('1000 LTC') / 5
        Value(value=200.00000000000000, denominator=1.00000000, network='litecoin')

        >>> Value('0.002 BTC') + 0.02
        Value(value=0.02200000000000, denominator=1.00000000, network='bitcoin')

        The Value class can be represented in several formats.

        # Examples: Format Value class
        >>> int(Value("10.1 BTC"))
        10

        >>> float(Value("10.1 BTC"))
        10.1

        >>> round(Value("10.123 BTC"), 2).str()
        '10.12000000 BTC'

        >>> hex(Value("10.1 BTC"))
        '0x3c336080'

        :param value: Value as integer, float or string. Numeric values must be supllied in smallest denominator such as Satoshi's. String values must be in the format: <value> [<denominator>][<currency_symbol>]
        :type value: int, float, str
        :param denominator: Denominator as integer or string. Such as 0.001 or m for milli, 1000 or k for kilo, etc. See NETWORK_DENOMINATORS for list of available denominator symbols.
        :type denominator: int, float, str
        :param network: Specify network if not supplied already in the value string
        :type network: str, Network

        """
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        if isinstance(denominator, str):
            dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
            if dens:
                denominator = dens[0]
        den_arg = denominator

        if isinstance(value, str):
            value_items = value.split()
            value = value_items[0]
            cur_code = self.network.currency_code
            den_input = 1
            if len(value_items) > 1:
                cur_code = value_items[1]
            network_names = [n for n in NETWORK_DEFINITIONS if
                             NETWORK_DEFINITIONS[n]['currency_code'].upper() == cur_code.upper()]
            if network_names:
                self.network = Network(network_names[0])
                self.currency = cur_code
            else:
                for den, symb in NETWORK_DENOMINATORS.items():
                    if len(symb) and cur_code[:len(symb)] == symb:
                        cur_code = cur_code[len(symb):]
                        network_names = [n for n in NETWORK_DEFINITIONS if
                                         NETWORK_DEFINITIONS[n]['currency_code'].upper() == cur_code.upper()]
                        if network_names:
                            self.network = Network(network_names[0])
                            self.currency = cur_code
                        elif len(cur_code):
                            raise ValueError("Currency symbol not recognised")
                        den_input = den
                        break
            self.value = float(value) * den_input
            self.denominator = den_input if den_arg is None else den_arg
        else:
            self.denominator = den_arg or 1.0
            self.value = float(value) * self.denominator

    def __str__(self):
        return self.str()

    def __repr__(self):
        return "Value(value=%.14f, denominator=%.8f, network='%s')" % \
               (self.value, self.denominator, self.network.name)

    def __int__(self):
        return int(self.value)

    def __float__(self):
        if self.value > self.network.denominator:
            return round(self.value, -int(math.log10(self.network.denominator)))
        else:
            return self.value

    def __lt__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value < other.value

    def __le__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value <= other.value

    def __eq__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot compare values from different networks")
            return self.value == other.value
        else:
            other = Value(other)
            return self.value == other.value and self.network == other.network

    def __ne__(self, other):
        return not self.__eq__(other)

    def __ge__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value >= other.value

    def __gt__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value > other.value

    def __add__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value + other) / self.denominator, self.denominator, self.network)

    def __iadd__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value + other) / self.denominator, self.denominator, self.network)

    def __isub__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value - other) / self.denominator, self.denominator, self.network)

    def __sub__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value - other) / self.denominator, self.denominator, self.network)

    def __mul__(self, other):
        return Value((self.value * other) / self.denominator, self.denominator, self.network)

    def __truediv__(self, other):
        return Value((self.value / other) / self.denominator, self.denominator, self.network)

    def __floordiv__(self, other):
        return Value(((self.value / self.denominator) // other), self.denominator, self.network)

    def __round__(self, n=0):
        val = round(self.value / self.denominator, n) * self.denominator
        return Value(val, self.denominator, self.network)

    def __index__(self):
        return self.value_sat

    def str(self, denominator=None, decimals=None, currency_repr='code'):
        """
        Get string representation of Value with requested denominator and number of decimals.

        >>> Value(1200000, 'sat').str('m')  # milli Bitcoin
        '12.00000 mBTC'

        >>> Value(12000.3, 'sat').str(1)  # Use denominator = 1 for Bitcoin
        '0.00012000 BTC'

        >>> Value(12000, 'sat').str('auto')
        '120.00 µBTC'

        >>> Value(0.005).str('m')
        '5.00000 mBTC'

        >>> Value(12000, 'sat').str('auto', decimals=0)
        '120 µBTC'

        >>> Value('13000000 Doge').str('auto')  # Yeah, mega Dogecoins...
        '13.00000000 MDOGE'

        >>> Value('2100000000').str('auto')
        '2.10000000 GBTC'

        >>> Value('1.5 BTC').str(currency_repr='symbol')
        '1.50000000 ₿'

        >>> Value('1.5 BTC').str(currency_repr='name')
        '1.50000000 bitcoins'

        :param denominator: Denominator as integer or string. Such as 0.001 or m for milli, 1000 or k for kilo, etc. See NETWORK_DENOMINATORS for list of available denominator symbols. If not provided the default self.denominator value is used. Use value 'auto' to automatically determine the best denominator for human readability.
        :type denominator: int, float, str
        :param decimals: Number of decimals to use
        :type decimals: float
        :param currency_repr: Representation of currency. I.e. code: BTC, name: bitcoins, symbol: ₿
        :type currency_repr: str

        :return str:
        """
        if denominator is None:
            denominator = self.denominator
        elif denominator == 'auto':
            # First try denominator=1 and smallest denominator (satoshi)
            if 0.001 <= self.value < 1000:
                denominator = 1
            elif 1 <= self.value / self.network.denominator < 1000:
                denominator = self.network.denominator
            else:  # Try other frequently used denominators
                for den, symb in NETWORK_DENOMINATORS.items():
                    if symb in ['n', 'fin', 'da', 'c', 'd', 'h']:
                        continue
                    if 1 <= self.value / den < 1000:
                        denominator = den
        elif isinstance(denominator, str):
            dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator[:len(symb)] and len(symb)]
            if len(dens) > 1:
                dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
            if dens:
                denominator = dens[0]
        if denominator in NETWORK_DENOMINATORS:
            den_symb = NETWORK_DENOMINATORS[denominator]
        else:
            raise ValueError("Denominator not found in NETWORK_DENOMINATORS definition")

        if decimals is None:
            decimals = -int(math.log10(self.network.denominator / denominator))
            if decimals > 8:
                decimals = 8
        if decimals < 0:
            decimals = 0
        balance = round(self.value / denominator, decimals)
        cur_code = self.network.currency_code
        if currency_repr == 'symbol':
            cur_code = self.network.currency_symbol
        if currency_repr == 'name':
            cur_code = self.network.currency_name_plural
        if 'sat' in den_symb and self.network.name == 'bitcoin':
            cur_code = ''
        return ("%%.%df %%s%%s" % decimals) % (balance, den_symb, cur_code)

    def str_unit(self, decimals=None, currency_repr='code'):
        """
        String representation of this Value. Wrapper for the :func:`str` method, but always uses 1 as denominator, meaning main denominator such as BTC, LTC.

        >>> Value('12000 sat').str_unit()
        '0.00012000 BTC'

        :param decimals: Number of decimals to use
        :type decimals: float
        :param currency_repr: Representation of currency. I.e. code: BTC, name: Bitcoin, symbol: ₿
        :type currency_repr: str
        :return str:
        """
        return self.str(1, decimals, currency_repr)

    def str_auto(self, decimals=None, currency_repr='code'):
        """
        String representation of this Value. Wrapper for the :func:`str` method, but automatically determines the denominator depending on the value.

        >>> Value('0.0000012 BTC').str_auto()
        '120 sat'

        >>> Value('0.0005 BTC').str_auto()
        '500.00 µBTC'

        :param decimals: Number of decimals to use
        :type decimals: float
        :param currency_repr: Representation of currency. I.e. code: BTC, name: Bitcoin, symbol: ₿
        :type currency_repr: str
        :return str:
        """

        return self.str('auto', decimals, currency_repr)

    @property
    def value_sat(self):
        """
        Value in the smallest denominator, i.e. Satoshi for the Bitcoin network

        :return int:
        """
        return round(self.value / self.network.denominator)

    def to_bytes(self, length=8, byteorder='little'):
        """
        Representation of value_sat (value in the smallest denominator: satoshi's) as bytes string. Used for script or transaction serialization.

        >>> Value('1 sat').to_bytes()
        b'\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00'

        :param length: Length of bytes string to return, default is 8 bytes
        :type length: int
        :param byteorder: Order of bytes: little or big endian. Default is 'little'
        :type byteorder: str

        :return bytes:
        """
        return self.value_sat.to_bytes(length, byteorder)

    def to_hex(self, length=16, byteorder='little'):
        """
        Representation of value_sat (value in the smallest denominator: satoshi's) as hexadecimal string.

        >>> Value('15 sat').to_hex()
        '0f00000000000000'

        :param length: Length of hexadecimal string to return, default is 16 characters
        :type length: int
        :param byteorder: Order of bytes: little or big endian. Default is 'little'
        :type byteorder: str
        :return:
        """
        return self.value_sat.to_bytes(length // 2, byteorder).hex()
