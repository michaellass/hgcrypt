# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from os import path, makedirs
from Convergent.Convergent import Convergent
from AESCBC import AESCBC
from hgcrypt import Hash

class DataCrypt:
    def __init__(self, cf):
        self.cf = cf
        key = cf.key
        self.cipher = Convergent(key)
        # self.cipher = AESCBC(key)

    def read(self):
        # We use an offset of 52 Bytes here because
        # we need so skip the following information:
        #  20 Bytes: Parent revision
        #  32 Bytes: Hash of corresponding metadata
        return self.cf.read(self.cf.reldatafile, offset=52)

    def store(self, existing=False, oldkey=None):
        print "Encrypting file", self.cf.fakename

        # If existing data should be evaluated (for reusing
        # the obfuscator) we need to read it here.
        # Otherwise make sure the obfuscator is reset.
        if existing:
            self.cipher.set_cdata(self.read(), oldkey=oldkey)
        else:
            self.cipher.obf = b''

        # Read in plain text, and encrypt it
        plainfh = open(self.cf.abspath, "rb")
        cdata = self.cipher.encrypt(plainfh.read())
        plainfh.close()

        # Store ctx, hash of metadata and encrypted data
        fh = open(self.cf.datafile, "wb")
        fh.write(self.cf.r.ctx.node())
        metahash = Hash.hash_files(self.cf.signedmetafiles(), compact=True)
        fh.write(metahash)
        fh.write(cdata)
        fh.close()

    def decrypt(self):
        print "Decrypting file", self.cf.id

        # make sure the target dir exists
        dirpath = self.cf.abspath.rsplit("/", 1)[0]
        if not path.exists(dirpath):
            makedirs(dirpath)

        self.cipher.set_cdata(self.read())
        fh = open(self.cf.abspath, "wb")
        fh.write (self.cipher.decrypt())
        fh.close()
