# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    © 2018 - 2019 March - 1200 Web Development <http://1200wd.com/>
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

# Modified fork of bitcoinlib: only the encoding module (and its config/main
# dependencies) is used by btcrecover. Upstream wallet/database/service modules
# have been removed to keep the bundled dependency minimal.
import lib.bitcoinlib_mod.encoding

__all__ = ["encoding", "networks"]
