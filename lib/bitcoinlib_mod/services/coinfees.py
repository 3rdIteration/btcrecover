# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Coinfees client
#    © 2017 May - 1200 Web Development <http://1200wd.com/>
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


from bitcoinlib.services.baseclient import BaseClient

PROVIDERNAME = 'coinfees'


class CoinfeesClient(BaseClient):

    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def compose_request(self, category, cmd, method='get'):
        url_path = category
        if cmd:
            url_path += '/' + cmd
        return self.request(url_path, method=method)

    def estimatefee(self, blocks):
        res = self.compose_request('fees', 'recommended')
        if blocks <= 1:
            return res['fastestFee'] * 1024
        elif blocks <= 2:
            return res['halfHourFee'] * 1024
        return res['hourFee'] * 1024
