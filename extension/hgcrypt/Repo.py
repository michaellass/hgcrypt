# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

import yaml
from os import makedirs, path
from hgcrypt import GPG, common
from hgcrypt.ConfidentialFile import ConfidentialFile

""" The class 'Repo' mainly does some housekeeping on local metadata.
    For storing this data it uses another class 'Datastore' """

class Datastore:
    def __init__(self):
        self.ignored_files = set([
            ".hgcrypt/private/hgignore",
            ".hgcrypt/private/data.yaml",
        ])
        self.verified = set()
        self.id2name = dict()
        self.name2id = dict()
        self.hashes = dict()
        self.to_be_added = set()
        self.to_be_deleted = set()
        self.to_be_moved = dict()
        self.to_be_merged = dict()
        self.to_be_obfuscated = set()
        self.new_perms = dict()
        self.fingerprint = None
        self.needpw = False

class Repo:
    def __init__(self, repo, init=False):
        self.repo = repo
        self.ctx = repo.parents()[0]
        self.mail = common.extract_mailaddr(repo.ui.username().decode("utf-8"))

        if self.mail == None:
            raise Exception("Please configure hg properly. You don't have a mail address.")

        self.repopath = repo.root + "/"
        self.datapath = self.repopath + ".hgcrypt/public/"
        self.metapath = self.repopath + ".hgcrypt/private/"

        if not path.exists(self.datapath):
            makedirs(self.datapath)
        if not path.exists(self.metapath):
            makedirs(self.metapath)

        if init:
            # create hgignore if it does not exist
            if not path.exists(self.metapath + "hgignore"):
                open(self.metapath + "hgignore", "a").close()
            # no further configuration needed so we quit here
            return

        self.load_data()
        if self.data.needpw:
            self.passphrase = repo.ui.getpass("Please enter passphrase for you key: ")

    def load_data(self):
        ui = self.repo.ui

        try:
            fh = open(self.metapath + "data.yaml", "r")
            self.data = yaml.load(fh)
            fh.close()
        except IOError:
            self.data = Datastore()
            self.data.fingerprint = GPG.select_fingerprint(self.repo)
            needpw = ui.promptchoice("Does this key have a passphrase? [Y/n]", ["&Yes", "&No"], 0)
            if needpw == 0:
                self.data.needpw = True
            self.store_data()

        if not GPG.check_uid_trust(self.data.fingerprint, self.mail):
            ui.write("Your private key does not match your mail address or is not trusted. You should fix that!\n")

    def store_data(self):
        fh = open(self.metapath + "data.yaml", "w")
        fh.write(yaml.dump(self.data))
        fh.close()
        self.store_hgignore()

    def store_hgignore(self):
        fh = open(self.metapath + "hgignore", "w")
        for fn in self.data.ignored_files:
            fh.write(fn + "\n")
        fh.close()

    def list_changed(self):
        files = set(self.data.id2name.keys()) - self.data.to_be_added \
            - self.data.to_be_deleted - set(self.data.to_be_moved.keys()) \
            - set(self.data.to_be_merged.keys())
        cfs = [ConfidentialFile(self, id=id, ctx=self.ctx) for id in files] \
            + [ConfidentialFile(self, id=id, ctx=self.repo[self.data.to_be_merged[id]])
                for id in self.data.to_be_merged.keys()]
        return [x for x in cfs if x.has_changed()]

    def list_cfs(self):
        files = self.data.id2name.keys()
        cfs = [ConfidentialFile(self, id=id, ctx=self.ctx) for id in files]
        return cfs

    def add_file(self, cf, todo=True):
        if todo:
            self.data.to_be_added.add(cf.id)
        self.data.id2name[cf.id] = cf.fakename
        self.data.name2id[cf.fakename] = cf.id
        self.data.ignored_files.add(cf.fakename)
        self.store_data()

    def remove_file(self, cf, todo=True):
        if todo:
            self.data.to_be_deleted.add(cf.id)
        name = self.data.id2name[cf.id]
        del self.data.id2name[cf.id]
        del self.data.hashes[cf.id]
        del self.data.name2id[name]
        self.data.ignored_files.remove(name)
        self.store_data()

    def move_file(self, cf, target, todo=True):
        oldname = cf.fakename
        if todo:
            if cf.id in self.data.to_be_moved.keys():
                oldname = self.data.to_be_moved[cf.id]
            self.data.to_be_moved[cf.id] = target
        del self.data.name2id[oldname]
        self.data.name2id[target] = cf.id
        self.data.id2name[cf.id] = target
        self.data.ignored_files.remove(oldname)
        self.data.ignored_files.add(target)
        self.store_data()

    def merge_file(self, cf):
        self.data.to_be_merged[cf.id] = cf.ctx.hex()
        self.store_data()

    def obfuscate_file(self, cf):
        self.data.to_be_obfuscated.add(cf.id)
        self.store_data()

    def new_perm(self, cf, identity, perm):
        if cf.id not in self.data.new_perms.keys():
            self.data.new_perms[cf.id] = dict()
        self.data.new_perms[cf.id][identity] = perm
        self.store_data()

    def id2name(self, id):
        return self.data.id2name[id]

    def name2id(self, name):
        return self.data.name2id[name]

    def hash(self, id):
        if id in self.data.hashes.keys():
            return self.data.hashes[id]
        else:
            return None

    def set_hash(self, id, hash):
        self.data.hashes[id] = hash

    def commit_done(self, filelist):
        self.data.to_be_added = set()
        self.data.to_be_deleted = set()
        self.data.to_be_moved = dict()
        self.data.to_be_merged = dict()
        self.data.to_be_obfuscated = set()
        self.data.new_perms = dict()
        for f in filelist:
            self.data.hashes[f.id] = f.build_hash()
        self.store_data()

    def verified(self, ctx):
        ver_revs = self.list_verified()
        if ctx.hex() in ver_revs:
            # already known to be verified
            return
        if ctx == self.repo["null"]:
            # trivial
            return
        obsolete = self.data.verified & set([x.hex() for x in ctx.ancestors()])
        self.data.verified.add(ctx.hex())
        self.data.verified -= obsolete
        self.store_data()

    def list_verified(self):
        # get all ancestors of verified revs because they were verified, too.
        # transform the result first into a flat list and then into a set.
        ver_ancestors = [list(self.repo[x].ancestors()) for x in self.data.verified]
        ver_ancestors = common.flatten(ver_ancestors)
        ver_revs = set([x.hex() for x in ver_ancestors]) | self.data.verified | set(["null"])
        return ver_revs

    def compare_revs(self, rev1, rev2):
        status = self.repo.status(node1=rev1, node2=rev2)

        # status contains multiple lists of files that were modified, added, removed etc...
        # in each list we look for elements that contain data of confidential files.
        # for those files we build tuples (id, filename)
        files = [[(x.split("/")[2], x.split("/")[3]) for x in filelist if ".hgcrypt/public/" in x]
            for filelist in status]

        # to increase readability we transform the list of lists into a dict of lists
        result = {"modified" : files[0],
               "added"   : files[1],
               "removed" : files[2],
               "deleted" : files[3],
               "unknown" : files[4],
               "ignored" : files[5],
               "clean"   : files[6]}
        return result

    def is_confidential(self, path):
        return path in self.data.name2id.keys()
