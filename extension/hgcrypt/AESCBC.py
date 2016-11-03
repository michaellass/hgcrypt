# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from Crypto.Cipher import AES
from hgcrypt import common

class AESCBC:
    def __init__(self, key):
        self.key = key
        self.cdata = b''

    def set_cdata(self, cdata, oldkey=None):
        self.cdata = cdata

    def decrypt(self):
        padding = ord(self.cdata[0])
        iv = self.cdata[1:17]
        plaindata = AES.new(self.key, AES.MODE_CBC, iv).decrypt(self.cdata[17:])
        return plaindata[:-padding]

    def encrypt(self, pdata):
        paddedlen = len(pdata)
        padding = 0
        if (paddedlen % 16 != 0):
            padding = 16 - (paddedlen % 16)
            paddedlen += padding
#            print "padded by ", padding, " to ", paddedlen
            pdata = pdata.ljust(paddedlen, b'\x00')
        iv = common.gen_random(16)
        cipher = chr(padding) + iv + AES.new(self.key, AES.MODE_CBC, iv).encrypt(pdata)
        return cipher
