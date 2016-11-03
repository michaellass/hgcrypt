# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

import sys
from os.path import dirname
sys.path.append(dirname(__file__))

from mercurial import commands, extensions
from mercurial.localrepo import localrepository
from hgcrypt import Repo, Dispatcher

def reposetup(ui, repo):
    # If repo is not local do nothing (probably pushing via SSH)
    if not isinstance(repo, localrepository):
        return

    r = Repo.Repo(repo, init=True)

    # Add extension specific ignore file to configuration
    ui.setconfig("ui", "ignore.hgcrypt",
        r.repopath + ".hgcrypt/private/hgignore")

def uisetup(ui):
    # Add hooks
    ui.setconfig("hooks", "post-status.hgcrypt", Dispatcher.poststatus)

    # Wrap commands
    extensions.wrapcommand(commands.table, 'add', Dispatcher.wrapped_add)
    extensions.wrapcommand(commands.table, 'commit', Dispatcher.wrapped_commit)
    extensions.wrapcommand(commands.table, 'update', Dispatcher.wrapped_update)
    extensions.wrapcommand(commands.table, 'rm', Dispatcher.wrapped_rm)
    extensions.wrapcommand(commands.table, 'mv', Dispatcher.wrapped_mv)
    extensions.wrapcommand(commands.table, 'merge', Dispatcher.wrapped_merge)
    extensions.wrapcommand(commands.table, 'revert', Dispatcher.wrapped_revert)

    # Manipulate parameters
    commands.table["^add"][1].append(tuple(['p', 'protected', False,
        'Mark files as confidential when adding them to repository']))

# Add new commands
cmdtable = {
    # "command-name": (function-call, options-list, help-string)
    "setacl": (Dispatcher.setacl, [], "hg setacl file user permission"),
    "listacl": (Dispatcher.listacl, [], "hg listacl file"),
    "obfuscate": (Dispatcher.obfuscate, [], "hg obfuscate file"),
    "lscf": (Dispatcher.lscf, [], "hg lscf"),
}
