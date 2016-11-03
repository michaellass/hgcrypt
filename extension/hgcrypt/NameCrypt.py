# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import common
from Crypto.Cipher import AES

class NameCrypt:
    def __init__(self, cf):
        self.cf = cf
        self.key = cf.key

    def read_name(self):
        enc_name = self.cf.read(self.cf.relnamefile)
        iv = enc_name[:16]
        enc_name = enc_name[16:]
        filename = AES.new(self.key, AES.MODE_CBC, iv).decrypt(enc_name)
        filename = filename.rstrip(b'\x00')
        return filename

    def store_name(self, name):
        iv = common.gen_random(16)
        paddedlen = len(name)
        if paddedlen % 16 != 0:
            paddedlen += 16 - (paddedlen % 16)
        filename = name.ljust(paddedlen, b'\x00')
        enc_name = AES.new(self.key, AES.MODE_CBC, iv).encrypt(filename)
        fh = open(self.cf.namefile, "wb")
        fh.write(iv)
        fh.write(enc_name)
        fh.close
