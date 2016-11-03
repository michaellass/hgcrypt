# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from Crypto.Hash import SHA256

def hash_data(data):
    hasher = SHA256.new(data=data)
    return hasher.digest()

def hash_datalist(datalist, compact=False):
    hashes = list()
    for data in datalist:
        hashes.append(hash_data(data))
    concat = b''.join(hashes)
    if compact:
        return hash_data(concat)
    else:
        return concat

def hash_files(filelist, compact=False):
    fhs = [open(f, mode="rb") for f in filelist]
    datalist = [fh.read() for fh in fhs]
    return hash_datalist(datalist, compact)

def hash_revisioned_files(filelist, ctx, compact=False):
    datalist = [ctx[path].data() for path in filelist]
    return hash_datalist(datalist, compact)
