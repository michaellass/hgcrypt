# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import common, Hash, Sign, GPG
from hgcrypt.DataCrypt import DataCrypt
from hgcrypt.KeyCrypt import KeyCrypt
from hgcrypt.NameCrypt import NameCrypt
from os import makedirs, path, unlink, rename
import yaml, base64

""" The class 'ConfidentialFile' represents a confidential file.
    It is used for creating, checking, modifying and decrypting those files.
    'FileMeta' is a small class that holds the metadata of a confidential file """

class FileMeta:
    def __init__(self, cf):
        self.writers = set([(cf.r.mail, cf.r.data.fingerprint)])
        self.readers = set()
        self.version = ""
        self.id = cf.id

class ConfidentialFile:
    def __init__(self, r, id=None, name=None, ctx=None):
        self.r = r
        self.ctx = ctx

        self.name = None
        self.fakename = None
        self.oldkey = None

        # determine who made this revision
        if ctx is not None and ctx.user() != "":
            self.mail = common.extract_mailaddr(ctx.user())

        # cur_rev stores the currently checked out revision
        cur_rev = r.ctx.hex()

        if ctx is None: # no ctx given, so this is a new file
            # initialized by name
            if id is None:
                assert name is not None
                self.id = common.gen_id(r.mail)
                self.name = name
                self.fakename = name
                self.r.add_file(self)
            # initialized by id
            else:
                assert name is None
                self.id = id
                self.fakename = self.r.id2name(id)

        else: # we have to read from a specific ctx
            assert id is not None
            assert name is None
            self.id = id

        # define paths of files that store information to this file
        self.datafile = r.datapath + self.id + "/data"
        self.reldatafile = ".hgcrypt/public/" + self.id + "/data"
        self.datasigfile = r.datapath + self.id + "/data.asc"
        self.reldatasigfile = ".hgcrypt/public/" + self.id + "/data.asc"
        self.keyfile = r.datapath + self.id + "/key"
        self.relkeyfile = ".hgcrypt/public/" + self.id + "/key"
        self.namefile = r.datapath + self.id + "/filename"
        self.relnamefile = ".hgcrypt/public/" + self.id + "/filename"
        self.metafile = r.datapath + self.id + "/meta"
        self.relmetafile = ".hgcrypt/public/" + self.id + "/meta"
        self.metasigfile = r.datapath + self.id + "/meta.asc"
        self.relmetasigfile = ".hgcrypt/public/" + self.id + "/meta.asc"

        # Initialize keycipher
        self.keycipher = KeyCrypt(self)

        # Is this an existing file?
        if self.ctx is not None and self.id not in r.data.to_be_added:
            self.metaobj = self.read_metadata()
            # If we can decrypt the file, initialize all necessary parts
            if self.can_decrypt():
                self.key = self.keycipher.read_key(self.r)
                self.namecipher = NameCrypt(self)
                self.datacipher = DataCrypt(self)
                self.name = self.namecipher.read_name()
                if self.id in self.r.data.id2name.keys():
                    self.fakename = self.r.id2name(self.id)
                else:
                    self.fakename = common.collisionfree_name(r, self.name)
            # else we are finished
            else:
                return

        # This is a new file
        else:
            self.metaobj = FileMeta(self)
            self.key = common.gen_random(32)
            self.namecipher = NameCrypt(self)
            self.datacipher = DataCrypt(self)

        if self.id in r.data.to_be_added:
            self.name = r.id2name(self.id)
            self.fakename = r.id2name(self.id)

        if self.fakename is not None:
            self.abspath = r.repopath + self.fakename

    def read(self, path, ctx=None, offset=0):
        if ctx is None:
            ctx = self.ctx
        return ctx[path].data()[offset:]

    def dataversion(self):
        return self.read(self.reldatafile)[:20]

    def storedmetahash(self):
        return self.read(self.reldatafile)[20:52]

    def store(self, obfuscate=False):
        assert self.name != None
        assert self.key != None
        if not path.exists(self.r.datapath + self.id):
            makedirs(self.r.datapath + self.id)
        fingerprints = [x[1] for x in self.readers()]
        self.keycipher.store_key(self.key, fingerprints)
        self.namecipher.store_name(self.name)
        self.sign_metadata()
        self.store_data(obfuscate=obfuscate)

    def store_name(self, name):
        self.namecipher.store_name(name)
        self.sign_metadata()
        self.store_data()

    def store_data(self, obfuscate=False):
        reuse_existing = not obfuscate
        self.datacipher.store(existing=reuse_existing, oldkey=self.oldkey)
        self.sign_data()

    def decrypt(self):
        self.datacipher.decrypt()
        self.r.set_hash(self.id, self.build_hash())

    def has_changed(self):
        if not self.can_decrypt():
            return False
        return self.r.hash(self.id) != self.build_hash()

    def build_hash(self):
        return Hash.hash_files([self.abspath])

    def can_decrypt(self):
        if self.ctx is None:
            return False
        if self.id in self.r.data.to_be_added:
            return False
        valid = self.verify_metadata()
        if valid == False:
            return False
        if not GPG.check_uid_trust(valid[1], self.owner()):
            return False
        return self.keycipher.read_key(self.r) != ""

    def can_write(self):
        return (self.r.mail, self.r.data.fingerprint) in self.metaobj.writers

    def metafiles(self):
        return [self.relkeyfile,
            self.relnamefile,
            self.relmetafile,
            self.relmetasigfile]

    def signedmetafiles(self):
        return [self.keyfile,
            self.namefile,
            self.metafile,
            ]

    def relsignedmetafiles(self):
        return [self.relkeyfile,
            self.relnamefile,
            self.relmetafile,
            ]

    def owner(self):
        encowner = self.id.split(".")[0]
        owner = base64.urlsafe_b64decode(encowner)
        return owner

    def remove(self):
        # here only the checked out version of the file is removed
        unlink(self.abspath)

    def signed_removal(self):
        to_be_deleted = self.relsignedmetafiles() + [self.reldatafile, self.reldatasigfile]

        hash = Hash.hash_data("deleted:" + self.id + ":" + self.ctx.hex())
        sig = Sign.sign_data(hash, self.r.data.fingerprint, self.r)
        fh = open(self.metasigfile, mode="wb")
        fh.write(sig)
        fh.close()

        return to_be_deleted

    def verify_removal(self, ctx):
        # we need the ctx as a parameter here because this object was
        # initialized with another ctx (probably the parent rev.)
        hash = Hash.hash_data("deleted:" + self.id + ":" + self.ctx.hex())
        sig = self.read(self.relmetasigfile, ctx=ctx)
        ver = Sign.verify_data(hash, sig)
        if ver == None:
            return False
        else:
            return (self.owner(), ver)


    def move_to(self, target):
        newabspath = self.r.repopath + target
        print self.abspath, "=>", newabspath
        parts = newabspath.rsplit("/", 1)
        if not path.exists(parts[0]):
            makedirs(parts[0])
        rename(self.abspath, newabspath)
        self.fakename = target
        self.abspath = newabspath

    def hash_metadata(self):
        return Hash.hash_revisioned_files(self.relsignedmetafiles(), self.ctx, compact=True)

    def sign_metadata(self):
        if self.ctx is not None:
            self.metaobj.version = self.ctx.hex()
        self.store_metadata()
        hash = Hash.hash_files(self.signedmetafiles())
        sig = Sign.sign_data(hash, self.r.data.fingerprint, self.r)
        fh = open(self.metasigfile, mode="wb")
        fh.write(sig)
        fh.close()

    def sign_data(self):
        hash = Hash.hash_files([self.datafile])
        sig = Sign.sign_data(hash, self.r.data.fingerprint, self.r)
        fh = open(self.datasigfile, mode="wb")
        fh.write(sig)
        fh.close()

    def verify_metadata(self):
        hash = Hash.hash_revisioned_files(self.relsignedmetafiles(), self.ctx, compact=False)
        sig = self.read(self.relmetasigfile)
        ver = Sign.verify_data(hash, sig) # FIXME: not taking time/date of commit into account
        if ver == None:
            return False
        else:
            return (self.owner(), ver)

    def verify_data(self):
        hash = Hash.hash_data(self.read(self.reldatafile))
        sig = self.read(self.reldatasigfile)
        ver = Sign.verify_data(hash, sig) # FIXME: not taking time/date of commit into account
        if ver == None:
            return False
        else:
            return (self.mail, ver)

    def store_metadata(self):
        fh = open(self.metafile, mode="w")
        fh.write(yaml.dump(self.metaobj))
        fh.close()

    def read_metadata(self):
        return yaml.load(self.read(self.relmetafile))

    def readers(self):
        return self.metaobj.writers | self.metaobj.readers

    def rekey(self):
        # remember key so that the obfuscator can be decrypted
        self.oldkey = self.key
        self.key = common.gen_random(32)
        print "new key generated"
        self.namecipher = NameCrypt(self)
        self.datacipher = DataCrypt(self)
        self.store(obfuscate=False)
        self.oldkey = None

    def permission(self):
        if (self.r.mail, self.r.data.fingerprint) in self.metaobj.writers:
            return "write"
        if (self.r.mail, self.r.data.fingerprint) in self.metaobj.readers:
            return "read"
        return "none"
