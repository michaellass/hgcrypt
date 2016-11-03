# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

import struct, re, base64
from Crypto import Random
from os import path
from hgcrypt.ConfidentialFile import ConfidentialFile

""" Collection of static functions
    that are used in various places """

def gen_random(length):
    return Random.new().read(length)

def gen_id(mail):
    id = base64.urlsafe_b64encode(mail)
    id += "."
    id += base64.urlsafe_b64encode(gen_random(32))
    return id

def encode_int(value):
    return struct.pack('!I', value)

def decode_int(value):
    return struct.unpack('!I', value)[0]

def extract_mailaddr(identifier):
    exp = re.compile(".*<(.*)>")
    res = exp.match(identifier).groups()
    if len(res) > 0:
        return res[0]
    else:
        return None

def get_relpath(repo, fn):
    if repo.getcwd() == "":
        relpath = fn
    else:
        relpath = repo.getcwd() + "/" + fn
    return path.normpath(relpath)

def collisionfree_name(r, name, dir=False):
    parts = name.rsplit("/", 1)
    if len(parts) > 1: # there is a dir in the name
        dirpath = collisionfree_name(r, parts[0], dir=True)
        name = dirpath + "/" + parts[1]

    if path.exists(r.repopath + name):
        # it is a dir and we want a dir
        if dir and path.isdir(r.repopath + name):
            return name

        # else look for an alternative name
        counter = 1
        while path.exists(r.repopath + name + str(counter)):
            counter += 1
        return name + str(counter)
    return name

def flatten(plist):
    result = list()
    for elem in plist:
        if isinstance(elem, list):
            result.extend(flatten(elem))
        else:
            result.append(elem)
    return result

def gen_cflist(r, ctx, cf_cache, cflist=None, idlist=None):
    """ generate a list of cf objects by reusing
        objects lying in a cache.
        can be called with a list of objects or ids """

    # we need either cflist or idlist
    assert cflist is not None or idlist is not None
    assert cflist is None or idlist is None

    if cflist is not None:
        # we have already a list of cf objects
        cfs = [x for x in cflist \
            if x.id not in cf_cache.keys()]
        cached_ids = set([x.id for x in cflist]) & set(cf_cache.keys())

    if idlist is not None:
        # we have a list of ids and need to create objects
        cfs = [ConfidentialFile(r, id=id, ctx=ctx) for id in idlist \
            if id not in cf_cache.keys()]
        cached_ids = set(idlist) & set(cf_cache.keys())

    for i in cached_ids:
        cfs.append(cf_cache[i])
    return cfs
