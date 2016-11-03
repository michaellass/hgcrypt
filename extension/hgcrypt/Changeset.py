# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import GPG, common
from hgcrypt.ConfidentialFile import ConfidentialFile

""" This class provides functionality to check changes of
    confidential files and to apply them in the working dir """
class Changeset:
    def __init__(self, r, ctx=None):
        self.r = r
        if ctx is None:
            self.checked_out = r.ctx
        else:
            self.checked_out = ctx

    ''' FIXME: is_valid should also make sure that contents in .hgcrypt/private
        are not touched in any revision. This is essential for security! '''
    def is_valid(self, ctx=None):
        if ctx is None:
            ctx = self.checked_out
        print "Checking", ctx

        # First revision of a repository is always valid
        if ctx == self.r.repo["null"]:
            return True

        # Is the revision already known to be valid?
        ''' FIXME: Previously checked revisions have to be invalidated if trust
            into foreign keys has changed (e.g. to detect malicious changes to
            confidential files we just gained access to). '''
        if ctx.hex() in self.r.list_verified():
            return True

        # Validate the parent(s)
        for parent in ctx.parents():
            if not self.is_valid(ctx=parent):
                return False

        # Validate changes from parent(s) to ctx
        if not self.is_valid_change(ctx.parents(), ctx):
            return False

        return True

    def is_valid_change(self, parents, ctx):
        print "Checking changes from", [str(p) for p in parents], "to", ctx
        status1 = self.r.compare_revs(parents[0], ctx)
        if len(parents) > 1:
            status2 = self.r.compare_revs(parents[1], ctx)

        # Get IDs of affected confidential files
        changed_ids = set([x[0] for x in status1["modified"] \
            + status1["added"] + status1["removed"]])
        if len(parents) > 1:
            changed_ids |= set([x[0] for x in status2["modified"] \
                + status2["added"] + status2["removed"]])

        # Validate changes of all of these files
        for id in changed_ids:
            print "  ", id, " changed"
            if not self.is_valid_filechange(id, parents[0], ctx, status1):
                if len(parents) == 1:
                    return False

                # there is a second parent, so check fallback on that change
                if not self.is_valid_filechange(id, parents[1], ctx, status2):
                    return False
        return True

    def is_valid_filechange(self, id, parent, ctx, status):

        # if data was removed we have to check for a valid remove operation
        if id in [x[0] for x in status["removed"]]:
            # the file does not exist anymore. use the object that belongs
            # to the parent revision here
            cf = ConfidentialFile(self.r, id=id, ctx=parent)
            fingerprint = cf.verify_removal(ctx)
            return self.is_valid_metaop(id, cf, fingerprint, parent, removal=True)

        cf = ConfidentialFile(self.r, id=id, ctx=ctx)
        # build paths of all files that were changed or added
        changed_files = set(['.hgcrypt/data/' + x[0] + '/' + x[1] for x in status["modified"] + status["added"]])

        if (changed_files & set(cf.relsignedmetafiles())) != set():
            print "    Metadata was changed"
            fingerprint = cf.verify_metadata()
            if not self.is_valid_metaop(id, cf, fingerprint, parent):
                return False

        if (cf.reldatafile in changed_files):
            print "    Content was changed"

            # does version match correct ctx?
            if cf.dataversion() != parent.node():
                print "!!! Content was changed on basis of wrong revision!"
                return False

            # is the stored reference on metadata correct?
            if cf.storedmetahash() != cf.hash_metadata():
                print "!!! Wrong metadata reference!"
                return False

            # check validiy of data signature
            datauser = cf.verify_data()
            if not datauser:
                print "!!! Signature of data could not be verified"
                return False

            if datauser not in cf.metaobj.writers:
                print "!!! File edited by unauthorized person!"
                return False

        return True

    def is_valid_metaop(self, id, cf, fingerprint, parent, removal=False):
        if not fingerprint:
            # The signature could not be checked. Signature incorrect
            # or public key unknown
            print("!!! Signature of metadata could not be verified.")
            return False

        if not cf.owner() == cf.mail:
            print("!!! Metadata was edited by user different from owner")
            return False

        if not GPG.mail_matches_fingerprint(cf.owner(), fingerprint[1]):
            print("!!! Key used for signing the metadata is not from owner")
            return False

        if not GPG.check_uid_trust(fingerprint[1], cf.owner()):
            print("WARNING: Key used for signing the metadata is not trusted. File cannot be used!")
            if cf.owner() == cf.r.mail:
                print("!!! This is your file. Possible manipulation!")
                return False

        # does metadata really belong to this file?
        if id != cf.metaobj.id:
            print "!!! Metadata invalid (belongs to different file)"
            return False

        # if the file was removed, we can stop here
        if removal:
            return True

        # does 'version' match the correct ctx?
        if cf.metaobj.version != parent.hex():
            print "!!! Metadata version does not match the correct revision!"
            return False

        # is the stored reference on metadata correct?
        if cf.storedmetahash() != cf.hash_metadata():
            print "!!! Wrong metadata reference in data file!"
            return False

        return True

    # Search for the latest common revision in the history of two revisions
    def latest_common_rev(self, ctx):
        common = set(ctx.ancestors()) \
            & set(self.checked_out.ancestors())
        if len(common) == 0:
            newest_common = self.r.repo["null"]
        else:
            newest_common = max(common, key=lambda x:x.rev())

        return newest_common

    # apply changes of confidential files in working copy
    def apply(self, oldctx):
        if oldctx == self.checked_out:
            # nothing to do
            return
        if oldctx in self.checked_out.ancestors():
            # we just go forward in history
            self.apply_streight(oldctx)
        elif self.checked_out in oldctx.ancestors():
            # we go backwards in history
            self.apply_streight(oldctx)
        elif self.r.repo["null"] in [oldctx, self.checked_out]:
            # we go to or come from "null"
            self.apply_streight(oldctx)
        else:
            # we have to go back to the latest common rev
            # and after that go forward to the new rev
            newest_common = self.latest_common_rev(oldctx)
            self.apply_streight(oldctx, goal=newest_common)
            self.apply_streight(newest_common, goal=self.checked_out)

    def apply_streight(self, oldctx, goal=None):
        if goal is None:
            goal = self.checked_out
        changes = self.r.compare_revs(oldctx, goal)

        print oldctx, "=>", goal

        # decrypt files that were added since oldctx and can be decrypted
        for file in set([x[0] for x in changes["added"]]):
            added_data = [x[1] for x in changes["added"] if x[0] == file]
            if added_data == ["meta.asc"]:
                # Meta signature without all the other files.
                # Probably the file was deleted, so ignore this.
                continue

            file = ConfidentialFile(self.r, id=file, ctx=goal)
            if file.can_decrypt():
                file.decrypt()
                self.r.add_file(file, False)

        # When data was changed (but not removed), analyze the change and act accordingly
        for file in set([x[0] for x in changes["modified"]]) \
                - set([x[0] for x in changes["removed"]]):
            file = ConfidentialFile(self.r, id=file, ctx=goal)
            changed_data = [x[1] for x in changes["modified"] if x[0] == file.id]

            if not file.can_decrypt():
                oldfile = ConfidentialFile(self.r, id=file.id, ctx=oldctx)
                if oldfile.can_decrypt():
                    # the right to read this file was revoked, so remove it
                    oldfile.remove()
                    self.r.remove_file(file, False)
            else:
                if "filename" in changed_data:
                    oldfile = ConfidentialFile(self.r, id=file.id, ctx=oldctx)
                    if oldfile.can_decrypt():
                        # double check that the file really was renamed
                        # we could also be here because of a changed key
                        if oldfile.name != file.name:
                            newname = common.collisionfree_name(self.r, file.name)
                            self.r.move_file(oldfile, newname, False)
                            file.move_to(newname)
                if "data" in changed_data:
                    file.decrypt()
                    self.r.add_file(file, False)

        # Remove files that were removed from repository
        for file in set([x[0] for x in changes["removed"]]):
            removed_data = [x[1] for x in changes["removed"] if x[0] == file]
            if removed_data == ["meta.asc"]:
                # Meta signature without all the other files.
                # Probably the file was deleted before, so ignore this.
                continue
            # check if we could decrypt the file before. otherwise there's nothing to do
            file = ConfidentialFile(self.r, id=file, ctx=oldctx)
            if file.can_decrypt():
                file.remove()
                self.r.remove_file(file, False)
