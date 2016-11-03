# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from sys import version_info
import random

class Rabin:
    """A class that provides all necessary peaces to calculate rolling
    hashes using the Rabin fingerprint algorithm."""

    def __init__(self, seed, wsize=48, prime=101, avgsize=512, minsize=48):
        self.precalc = []
        self.bytemap = []
        self.pos = 0
        self.lastpos = 0
        self.len = 0
        self.hash = 0
        self.hashmax = 0xffffffff
        self.minsize = minsize
        self.wsize = wsize
        self.prime = prime
        self.threshold = 2**32 / (avgsize - minsize + 1)

        random.seed(seed)
        maxmulti = (prime ** wsize) & self.hashmax
        for i in range(256):
            self.bytemap.append(random.randint(0, self.hashmax))
            self.precalc.append((self.bytemap[i] * maxmulti) & self.hashmax)

    def set_data(self, data):
        self.len = len(data)
        if version_info.major < 3:
            self.data = bytearray(data)
        else:
            self.data = data
        self.reset_pos()

    def reset_pos(self):
        self.hash = 0
        wsize = min(self.wsize, self.len)
        for i in range(wsize):
            self.hash = (self.prime * (self.hash + self.bytemap[self.data[i]])) & self.hashmax
        self.pos = wsize

    def next_block(self):
        while True:
            if not self.next():
                return -1
            if self.fulfilles_criteria():
                self.lastpos = self.pos
                return self.pos

    def fulfilles_criteria(self):
        if self.pos > self.len:
            return True
        if self.pos - self.lastpos < self.minsize:
            return False
        if self.hash < self.threshold:
            return True
        return False

    def next(self):
        if self.pos > self.len:
            return False
        if self.pos == self.len:
            self.pos += 1
            return True
        self.hash = (self.prime * (self.hash \
                - self.precalc[self.data[self.pos-self.wsize]] \
                + self.bytemap[self.data[self.pos]])) & self.hashmax
        self.pos += 1
        return True
