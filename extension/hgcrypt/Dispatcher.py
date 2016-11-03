# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import GPG, common
from hgcrypt.Changeset import Changeset
from hgcrypt.Repo import Repo
from hgcrypt.ConfidentialFile import ConfidentialFile
from mercurial import commands
from os import path

""" In this file all hooks and wrapped mercurial commands
    are defined.

    TODO: Several operations have not been implemented as their functionality is
    not essential to demonstrate the concept, e.g. log and diff."""

def poststatus(ui, repo, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    """ Extend 'hg status' by actions regarding
        confidential files. Used abbreviations:
          AC: add
          RC: remove
          NC: rename
          MC: modified
          OC: obfuscate
          PC: permission change
    """

    for id in r.data.to_be_added:
        cf = ConfidentialFile(r, id=id, ctx=ctx)
        ui.write("AC " + cf.fakename + "\n")
    for id in r.data.to_be_deleted:
        cf = ConfidentialFile(r, id=id, ctx=ctx)
        ui.write("RC " + cf.fakename + "\n")
    for id in r.data.to_be_moved.keys():
        cf = ConfidentialFile(r, id=id, ctx=ctx)
        ui.write("NC " + cf.name + " => " + r.data.to_be_moved[id] + "\n")
    for cf in r.list_changed():
        ui.write("MC " + cf.fakename + "\n")
    for id in r.data.to_be_obfuscated:
        cf = ConfidentialFile(r, id=id, ctx=ctx)
        ui.write("OC " + cf.fakename + "\n")
    for id in r.data.new_perms.keys():
        cf = ConfidentialFile(r, id=id, ctx=ctx)
        ui.write("PC " + cf.fakename + "\n")
        # for changed permissions also show what exactly will be changed
        for user in r.data.new_perms[cf.id].keys():
            ui.write("   " + str(user) + ": ")
            ui.write(r.data.new_perms[cf.id][user] + "\n")

def wrapped_add(orig_add, ui, repo, *args, **kwargs):
    r = Repo(repo)

    # If the -p parameter was given, generate a ConfidentialFile
    if kwargs['protected']:
        for elem in args:
            if not path.exists(elem):
                ui.write(elem + " not found. Ignoring...\n")
                continue
            relpath = common.get_relpath(repo, elem)
            # TODO: check if already part of repo as unconfidential
            if r.is_confidential(relpath):
                ui.write(elem + " already part of repository.\n")
            else:
                cf = ConfidentialFile(r, name=relpath)

    # otherwise just do a normal 'hg add'
    # here we have to make sure not to add confidential files!
    else:
        new_args = list()
        for elem in args:
            relpath = common.get_relpath(repo, elem)
            if not r.is_confidential(relpath):
                new_args.append(elem)
            else:
                ui.write(elem + " is confidential. Ignoring.\n")
        if len(new_args) > 0:
            return orig_add(ui, repo, *args, **kwargs)

def wrapped_commit(orig_commit, ui, repo, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    # we have to remember new or changed files so that we can
    # refresh the corresponding hash values
    commited_files = set()

    # change ACLs of files
    files = r.data.new_perms.keys()
    cfs = [ConfidentialFile(r, id=id, ctx=ctx) for id in files]
    for cf in cfs:
        for user in r.data.new_perms[cf.id].keys():
            permission = r.data.new_perms[cf.id][user]
            if permission == "write":
                cf.metaobj.writers.add(user)
                if user in cf.metaobj.readers:
                    cf.metaobj.readers.remove(user)
            elif permission == "read":
                cf.metaobj.readers.add(user)
                if user in cf.metaobj.writers:
                    cf.metaobj.writers.remove(user)
            elif permission == "none":
                if user in cf.metaobj.readers:
                    cf.metaobj.readers.remove(user)
                if user in cf.metaobj.writers:
                    cf.metaobj.writers.remove(user)
        # Change key of confidential file
        cf.rekey()
    # cache all cf objects here. because of the changed key we have to
    # reuse them if any other operations are done with the corresponding file
    cf_cache = dict((cf.id, cf) for cf in cfs)

    # encrypt changed files
    cfs = common.gen_cflist(r, ctx, cf_cache, cflist=r.list_changed())
    for cf in cfs:
        if not cf.can_write():
            ui.write("You have no permission to edit the file '" \
                + cf.fakename + "'. It will not be commited.\n")
        else:
            cf.store_data()
            commited_files.add(cf)

    # add new files
    files = r.data.to_be_added
    cfs = [ConfidentialFile(r, id=id) for id in files]
    for cf in cfs:
        # the cf does not know the current ctx, so we set it here
        cf.metaobj.version = ctx.hex()
        cf.store(obfuscate=True)
    commited_files |= set(cfs)
    filelist = [r.datapath + cf.id for cf in cfs]
    if len(filelist) > 0:
        commands.add(ui, repo, *filelist)

    # remove deleted files
    files = r.data.to_be_deleted
    cfs = [ConfidentialFile(r, id=id, ctx=ctx) for id in files]
    to_remove = [cf.signed_removal() for cf in cfs]
    for step in to_remove:
        commands.remove(ui, repo, *step)

    # move files
    cfs = common.gen_cflist(r, ctx, cf_cache, idlist=r.data.to_be_moved.keys())
    for cf in cfs:
        cf.store_name(r.data.to_be_moved[cf.id])

    # obfuscate files
    cfs = common.gen_cflist(r, ctx, cf_cache, idlist=r.data.to_be_obfuscated)
    for cf in cfs:
        cf.store_data(obfuscate=True)

    orig_commit(ui, repo, *args, **kwargs)

    # remove all pending actions because they were done successfully
    # also refresh hashes of changed plaintext files
    r.commit_done(commited_files)

def wrapped_merge(orig_merge, ui, repo, *args, **kwargs):
    r = Repo(repo)
    co_parent = r.ctx
    new_parent = repo[args[0]]
    ui.write("merging " + str(new_parent) + " into " + str(co_parent) + "\n")

    # Verify revision that should be merged
    changeset = Changeset(r, new_parent)
    if not changeset.is_valid():
        ui.write("The revision to be merged could not be verified. STOP\n")
        return
    r.verified(new_parent)

    # Get latest common revision between the two
    last_common = changeset.latest_common_rev(co_parent)

    # Check if a confidential file was modified in both branches.
    # In this case there is a conflict. This would have to be resolved
    # by a person with sufficient rights. Not implemented here...
    diff1 = r.compare_revs(last_common, co_parent)
    diff2 = r.compare_revs(last_common, new_parent)
    common_changes = set(diff1["modified"]) & set(diff2["modified"])
    if len(common_changes) > 0:
        ui.write("Revisions are incompatible as there were changes to a confidential file in both revisions\n")
        return

    orig_merge(ui, repo, *args, **kwargs)

    # Apply all changes to confidential files
    # between the latest common rev and the revision we just merged
    changeset.apply(last_common)

    # remember confidential files that were added by doing the merge
    for id in set([x[0] for x in diff2["added"]]):
        r.merge_file(ConfidentialFile(r, id=id, ctx=new_parent))

def wrapped_update(orig_update, ui, repo, *args, **kwargs):
    r = Repo(repo)
    oldctx = r.ctx
    if len(args) != 0:
        newctx = repo[args[0]]
    else:
        # if no argument was given, we want to checkout the newest revision
        newctx = repo.changectx(repo.changelog.tip())

    # If there are outstanding changes, quit immediately
    if (r.data.to_be_added | r.data.to_be_deleted | r.data.to_be_obfuscated) != set() or \
        r.data.to_be_moved != dict() or r.data.to_be_merged != dict():
        ui.write("Please commit your changes before up/co\n")
        return

    # Verify revision before really doing a checkout
    changeset = Changeset(r, ctx=newctx)
    if not changeset.is_valid():
        ui.write("The revision could not be verified. STOP!\n")
        return
    r.verified(newctx)

    orig_update(ui, repo, *args, **kwargs)

    # Apply changes to confidential files
    changeset.apply(oldctx)
    ui.write("Successfully updated from " + str(oldctx) + " to " + str(newctx) + "\n")

def wrapped_rm(orig_rm, ui, repo, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    # for confidential files we have to do a signed removal
    # for other files we just do a normal hg rm
    new_args = list()
    for elem in args:
        relpath = common.get_relpath(repo, elem)
        if r.is_confidential(relpath):
            cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)
            if cf.owner() != r.mail:
                ui.write(cf.fakename + " is not your file. You cannot remove it.\n")
                continue
            cf.remove()
            r.remove_file(cf)
        else:
            new_args.append(elem)
    if len(new_args) > 0:
        return orig_rm(ui, repo, *new_args, **kwargs)

def wrapped_mv(orig_mv, ui, repo, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    new_args = list()
    target = args[-1]
    target_is_dir = False

    # Protect against overwriting an existing target
    if path.exists(target):
        if path.isdir(target):
            target_is_dir = True
        else:
            ui.write("Target already exists. Aborting\n")
            return

    # If target is no dir, make sure there is only one source
    if not target_is_dir and len(args) != 2:
        ui.write("Incorrect number of parameters.\n")

    target = common.get_relpath(repo, target)

    # distinguish between confidential and unconfidential sources
    for elem in args[:-1]:
        relpath = common.get_relpath(repo, elem)
        if r.is_confidential(relpath):
            cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)
            if cf.owner() != r.mail:
                ui.write(cf.fakename + " is not your file. You cannot rename it.\n")
                continue
            if target_is_dir:
                ui.write("For moving confidential files please specify complete path.\n")
                continue
            r.move_file(cf, target)
            cf.move_to(target)
        else:
            new_args.append(elem)
    if len(new_args) > 0:
        new_args.append(args[-1])
        return orig_mv(ui, repo, *new_args, **kwargs)

def wrapped_revert(orig_revert, ui, repo, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    new_args = list()

    # distinguish between confidential and unconfidential files
    for elem in args:
        relpath = common.get_relpath(repo, elem)
        if r.is_confidential(relpath):
            # if it is confidential, just redecrypt
            cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)
            cf.decrypt()
        else:
            # otherwise we will pass the file to orig_revert
            new_args.append(elem)
    if len(new_args) > 0:
        return orig_revert(ui, repo, *new_args, **kwargs)

def setacl (ui, repo, file, user, permission, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    relpath = common.get_relpath(repo, file)
    if not r.is_confidential(relpath):
        ui.write("That file is not confidential. So there are no ACLs.\n")
        return

    cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)
    if cf.owner() != r.mail:
        ui.write("This is not your file. You cannot change ACLs\n")
        return

    if permission not in ["read", "write", "none"]:
        ui.write("Please choose the permission from 'read', 'write' or 'none'.\n")
        return

    keys = GPG.search_by_mail(user)

    # If there are no known keys for the user, ask for an ID/Fingerprint
    if len(keys) == 0:
        keyid = ui.prompt("No public key for that user known. Please enter a key ID or a fingerprint")
        key = GPG.search_by_id(keyid)
        if not key:
            ui.write("Could not find such a key\n")
            return
        if not GPG.mail_matches_fingerprint(user, key['fingerprint']):
            ui.write("That key does not belong to that user\n")
            return
    # Otherwise let the user choose a key
    else:
        ids = [str(x['keyid']) for x in keys]
        ui.write("Known keys:\n")
        for id in ids:
            ui.write(" " + id + "\n")
        key = None
        while key is None:
            keyid = ui.prompt("Key-ID: ")
            if keyid in ids:
                index = ids.index(keyid)
                key = keys[index]
    fingerprint = key['fingerprint']

    # if permissions are granted (and not revoked) the key must be trusted
    if permission in ["read", "write"] and not GPG.check_uid_trust(fingerprint, user):
        ui.write("You do not trust the given key.\n")
        return

    # the owner should not remove his/her own key from ACLs
    if user == r.mail and fingerprint == r.data.fingerprint:
        ui.write("You cannot change permissions for your own key.\n")
        return

    # Store new ACLs
    r.new_perm(cf, (user, fingerprint), permission)

def listacl (ui, repo, file, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    relpath = common.get_relpath(repo, file)
    if not r.is_confidential(relpath):
        ui.write("That file is not confidential. So there are no ACLs.\n")
        return

    cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)

    ui.write("Write permissions:\n")
    writers = [x[0] for x in cf.metaobj.writers]
    for writer in writers:
        ui.write(" " + writer + "\n")

    ui.write("Read permissions:\n")
    readers = [x[0] for x in cf.metaobj.readers]
    for reader in readers:
        ui.write(" " + reader + "\n")

def obfuscate(ui, repo, file, *args, **kwargs):
    r = Repo(repo)
    ctx = r.ctx

    relpath = common.get_relpath(repo, file)
    if not r.is_confidential(relpath):
        ui.write("That file is not confidential. So nothing to do here.\n")
        return

    cf = ConfidentialFile(r, id=r.name2id(relpath), ctx=ctx)

    if not cf.can_write():
        ui.write("You dont have permission to edit this file\n")
        return

    r.obfuscate_file(cf)

def lscf(ui, repo, *args, **kwargs):
    """ print a list of all decrypted confidential files in the following format:
          local filename (owner) - permissions of local user """
    r = Repo(repo)

    cfs = r.list_cfs()
    for cf in cfs:
        ui.write(cf.fakename + " (" + cf.owner() + ") - " + cf.permission() + "\n")

        # if the file was renamed because of a local conflict also show real name
        if (cf.name != cf.fakename):
            ui.write("    WARNING: Original filename: " + cf.name + "\n")
