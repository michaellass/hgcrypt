Readme
======

hgcrypt is a prototypical Mercurial extension, implementing fine-grained access
control in Mercurial repositories.

Provided Functionality
----------------------
This extension allows users to mark files as confidential, allowing them to
enforce fine-grained access control on these files. Read and write permission
can be given to other users who are identified and authenticated using OpenPGP.
Since Mercurial is a distributed system, enforcement of access rights is done
locally by each client.

The following operations are provided by hgcrypt:

* `hg add -p` adds files to version control and marks them as confidential
* `hg commit` automatically encrypts contents of confidential files before
  commiting them to the repository
* `hg update` validates changes before applying them to the local working copy
  and ensures that changes to confidential files have only been performed by
  authorized users. Also it automatically decrypts confidential files the user
  has access to.
* `hg lscf` lists all confidential files the user has access to
* `hg listacl` shows read and write permissions of a confidential file
* `hg setacl` allows owners of confidential files to change access rights
* `hg obfuscate` allows changing the obfuscator of a confidential file.
  Basically this enforces CCA-secure re-encryption of the file, loosing storage
  efficiency. Details can be obtained from the paper.

Required Software
-----------------
For using the Mercurial extension several other software components are
required. For development the following software versions have been used, so
using different versions may require changes.

* Python: 2.7.3
* Mercurial: 2.4.1
* PyCrypto: 2.6
* PyYAML: 3.10
* python-gnupg: 0.3.2 (included in this git repository)
* gnupg: 1.4.13
* Cython: 0.19 (optional)

Setup
-----
To use the extension, copy it to some place accessible by all users. In the
following example we choose `/opt/hgcrypt` for that.

__Optional__: If Cython is available, it is strongly recommended to compile the
corresponding version of the Rabin fingerprint algorithm. If this is not done
the extension automatically uses a significantly slower implementation in
Python.

    root # cp -r extension /opt/hgcrypt
    root # cd /opt/hgcrypt/hgcrypt/Convergent/rabin && ./build.sh    (optional)

Creating a test environment
---------------------------
The following is a simple demonstration of the extension's functionality.
Therefore we create two distinct users on the system. These users each need an
own PGP key which is known to all other users.

As an example, we create users `test1` and `test2`. When creating PGP keys we
choose test1@example.com and test2@example.com as email addresses and do not
set any passphrase (for simplicity).

    root # adduser test1
    root # adduser test2

    root # sudo -i -u test1
    test1# gpg --gen-key
    test1# gpg --output /tmp/test1.gpg --export test1@example.com
    test1# exit

    root # sudo -i -u test2
    test2# gpg --gen-key
    test2# gpg --output /tmp/test2.gpg --export test2@example.com
    test2# gpg --import /tmp/test1.gpg
    test2# exit

    root # sudo -i -u test1
    test1# gpg --import /tmp/test2.gpg
    test1# exit

Now we need to create the repositories of the users. We also create a third
repository that can be accessed by both users to simplify pulling and pushing
changes.

    root # mkdir /var/lib/repo
    root # cd /var/lib/repo
    root # hg init
    root # chmod -R 777 .

For X ∈ {1,2}:

    testX# mkdir repo
    testX# cd repo
    testX# hg init

    testX# cat > ~/.hgrc
    [ui]
    username = TestuserX <testX@example.com>
    Ctrl+D

    testX# cat > .hg/hgrc
    [paths]
    default = /var/lib/repo

    [extensions]
    hgcrypt = /opt/hgcrypt/hgcrypt.py
    Ctrl+D

Examplary operations
--------------------
After the initial setup above, the extension can be tested. For specific
operations trust into keys of other users is required. The following example
shows signing the key of `test2` by `test1` to allow him to use confidential
files owned by `test2`. Similarly, signing the key of `test1` by `test2` is also
required in order to grant access rights.

    test1# gpg --edit-key test2@example.com
    gpg> sign
    gpg> save

Following is an example to test the basic functionality of the extension. At
first use, you will be asked if your key is protected by a passphrase. If you
followed the setup above, answer with `n`.

    test2# echo "Some content" > testfile
    test2# hg add -p testfile
    test2# hg commit
    test2# hg lscf
    test2# hg listacl testfile
    test2# hg setacl testfile test1@example.com read
    test2# hg commit
    test2# hg push

    test1# hg pull
    test1# hg up 0    (content not accessible)
    test1# hg up      (read access was granted, file becomes visible)
    test1# hg listacl testfile

__Notice__: The extension currently produces very verbose output, showing each
single step during encryption/signing decryption/verification. Note that this
extension is a proof of concept only to demonstrate the concept shown in our
paper. It is not suitable for use in production.

Known bugs and limitations
--------------------------
* Key revocation and expiration: Signatures and trust are currently only
  verified with respect to the current point of time. If a GnuPG key of a user
  who made changes to confidential files is revoked or expires, revisions
  containing the respective change can no longer be verified successfully. (Some
  changes to our use of GnuPG are required to allow verification with respect to
  prior timestamps.)
* WoT changes: If a user starts trusting an owner whose files were previously
  hidden from her virtual view, the corresponding revisions have to be rechecked
  for authenticity. This is currently not performed automatically.
* Merging: Multiple changes to confidential files can only be merged by users
  who are authorized for the respective modifications, i.e., metadata changes
  can only be merged by file owners, contents can only be merged by
  write-authorized users. If revisions contain multiple changes to different
  confidential files, there might exist no user that is authorized to merge all
  confidential files. This can only be resolved by manual creation of
  intermediary revisions that merge only changes to those confidential files the
  merging user is authorized for. (Details on this are covered in the paper.)
* File name conflicts: As file names of confidential files are confidential,
  multiple confidential files with identical plaintext names might reside in a
  single folder. Conflicts across multiple confidential files are resolved
  automatically by renaming the respective files locally. Conflicts with
  non-confidential files, however,---e.g., if an unencrypted file is introduced
  by a user that does not have access to an already existing confidential file
  with similar name---might lead to undefined behaviour.
* Usability: Some operations (e.g., log, diff) do not account for the plaintexts
  of confidential files. Their usage is safe, though.
* Security: .hgcrypt/private caches security-related data like results of
  signature verifications. It is therefore essential for security that data
  stored at this location cannot be modified, e.g., by checking out
  unauthenticated data. As this is only a prototype, we have not verified and
  therefore cannot guarantee that this is the case in all possible situations.

References
----------
    Michael Lass, Dominik Leibenger and Christoph Sorge
    Confidentiality and Authenticity for Distributed Version Control Systems — A Mercurial Extension
    41st Annual IEEE Conference on Local Computer Networks (LCN), 2016
