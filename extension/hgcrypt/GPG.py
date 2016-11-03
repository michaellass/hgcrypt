# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from hgcrypt import common
from hgcrypt.external.gnupg.gnupg import GPG
import re
from os import environ

# Configuration
keyserver = "pgp.mit.edu"
trusted = ["ultimate", "full"]

def search_by_mail(mail, private=False):
    exp = re.compile(".*<" + mail + ">", re.I)
    g = GPG()
    keys = g.list_keys(private)
    matching = [x for x in keys if any([exp.match(y) is not None for y in x['uids']])]
    return matching

def search_by_fingerprint(fingerprint, private=False):
    g = GPG()
    keys = g.list_keys(private)
    matching = [x for x in keys if x['fingerprint'] == fingerprint]
    if len(matching) == 0:
        return False
    return matching[0]

def search_by_id(id, private=False):
    g = GPG()
    keys = g.list_keys(private)
    matching = [x for x in keys if x['keyid'] == id]
    if len(matching) == 0:
        # no key with that id is known. try to fetch it from a key server
        print "trying to fetch key from server: ", id
        res = g.recv_keys(keyserver, id)
        if res.count > 0:
            keys = [search_by_fingerprint(x) for x in res.fingerprints]
            matching.extend(keys)
        else:
            return False
    return matching[0]

def mail_matches_fingerprint(mail, fingerprint):
    # if the key with the specified fingerprint is not known try to fetch it
    if not search_by_fingerprint(fingerprint):
        search_by_id(fingerprint)

    # look for a key with the given mail address and fingerprint
    mail_matches = search_by_mail(mail)
    matches = [x for x in mail_matches if x['fingerprint'] == fingerprint]
    return len(matches) > 0

def select_fingerprint(repo):
    ui = repo.ui
    username = ui.username().decode("utf-8")
    mail = common.extract_mailaddr(username)

    keys = search_by_mail(mail, True)

    if len(keys) == 0:
        raise Exception("No private key for your email found")

    if len(keys) == 1:
        return keys[0]['fingerprint']
    else:
        ui.write("Which private key should be used?\n")
        ids = [str(x['keyid']) for x in keys]
        for id in ids:
            ui.write(" " + id + "\n")
        key = None
        while key is None:
            keyid = ui.prompt("Key-ID: ")
            if keyid in ids:
                index = ids.index(keyid)
                key = keys[index]
        return key['fingerprint']

''' TODO: As for Sign::verify_data we need a way to determine trust wrt. to a
    given point in time in order to verify old revisions.'''
def check_uid_trust(fingerprint, mail):
    if not mail_matches_fingerprint(mail, fingerprint):
        return False

    # call GPG to show all uids for the key with the given fingerprint
    # and also show trust values for all uids
    g = GPG()
    args = "--list-options show-uid-validity --list-sigs " + fingerprint
    args = [args]
    lang = environ["LANG"]
    environ["LANG"] = "C"
    p = g._open_subprocess(args)
    environ["LANG"] = lang
    result = p.stdout.readlines()

    # look for entries with the correct mail address and collect
    # trust values in a list
    exp = re.compile("uid\s*\[(.*)\].*\<" + mail + "\>")
    trust = list()
    for line in result:
        match = exp.match(line)
        if match is not None:
            trust.append(match.groups()[0].strip())

    # if any of the values matches with values in "trusted" we
    # trust the combination of fingerprint and mail address
    return any([x in trusted for x in trust])
