# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import GPG as GPGHelper
from hgcrypt.external.gnupg.gnupg import GPG

class KeyCrypt:
    def __init__(self, cf):
        self.cf = cf

    def read_key(self, r):
        enckey = self.cf.read(self.cf.relkeyfile)
        if r.data.needpw:
            return GPG().decrypt(enckey, passphrase=r.passphrase).data
        return GPG().decrypt(enckey).data

    def store_key(self, key, recipients):
        # We need the public key of all recipients to properly encrypt the key
        for rec in recipients:
            if GPGHelper.search_by_fingerprint(rec) == False:
                print "Trying to import the key for", rec
                res = GPGHelper.search_by_id(rec)
                if res == False:
                    raise Exception("No public key for " + str(rec) + " found")

        # We use always_trust here because we want to encrypt the key also for users
        # who we do not trust directly but who were specified by the file owner
        enckey = GPG().encrypt(key, recipients, armor=False, always_trust=True).data
        fh = open(self.cf.keyfile, "wb")
        fh.write(enckey)
        fh.close
