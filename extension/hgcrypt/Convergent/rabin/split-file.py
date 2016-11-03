#!/usr/bin/python

# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

try:
    from FastRabin import Rabin
    print("Using FastRabin")
except ImportError:
    from Rabin import Rabin
    print("Using slow Rabin")

rab = Rabin(0)
file = open("testfile", mode='rb')

rab.set_data(file.read())

while True:
    blockaddr = rab.next_block()
    if blockaddr == -1:
        break
    print ("New block at " + str(blockaddr))
