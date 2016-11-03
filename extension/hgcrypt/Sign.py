# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from tempfile import mkstemp
from os import unlink
from hgcrypt import GPG as GPGHelper
from external.gnupg.gnupg import GPG, _make_binary_stream

def sign_data(data, fingerprint, r):
    g = GPG()
    if r.data.needpw:
        obj = g.sign(data, binary=True, detach=True, keyid=fingerprint, passphrase=r.passphrase)
    else:
        obj = g.sign(data, binary=True, detach=True, keyid=fingerprint)
    return obj.data

''' TODO: Currently we have no possibility of verifying a signature wrt. to a
    specific point in time. This would be necessary in
    ConfidentialFile::verify_data and ConfidentialFile::verify_metadata in order
    to correctly verify old revisions after a key has expired or has been
    revoked.'''
def verify_data(data, signature):
    g = GPG()
    signature_stream = _make_binary_stream(signature, "utf-8")
    fh, fpath = mkstemp()
    fhw = open(fpath, mode="wb")
    fhw.write(data)
    fhw.close()
    obj = g.verify_file(signature_stream, data_filename=fpath)
    if not obj.valid: # probably just the key is not known
        keyid = obj.key_id
        GPGHelper.search_by_id(keyid)
        signature_stream = _make_binary_stream(signature, "utf-8")
        obj = g.verify_file(signature_stream, data_filename=fpath)
    unlink(fpath)
    if not obj.valid:
        return None
    else:
        return obj.pubkey_fingerprint
