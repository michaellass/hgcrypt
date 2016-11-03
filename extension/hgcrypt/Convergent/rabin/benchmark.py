#!/usr/bin/python

# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

import time

def calc_blocks(rab):
    while True:
        blockaddr = rab.next_block()
        if blockaddr == -1:
            return

file = open("testfile", mode='rb')
data = file.read()
file.close()

try:
    # Measuring Fast Rabin
    from FastRabin import Rabin as FastRabin
    fastrab = FastRabin(0)
    duration = 0
    for i in range(200):
        start = time.clock()
        fastrab.set_data(data)
        calc_blocks(fastrab)
        stop = time.clock()
        duration += stop-start

    print ("  Fast Rabin:", str(duration))
    throughput = 200 * len(data) / (duration) / 1024**2
    print ("    Throughput:", throughput)
    del fastrab
except ImportError:
    print("  FastRabin not available")

from Rabin import Rabin as SlowRabin
slowrab = SlowRabin(0)

# Measuring Slow Rabin
start = time.clock()
slowrab.set_data(data)
calc_blocks(slowrab)
stop = time.clock()
print ("  Slow Rabin:", str(stop-start))
throughput = len(data) / (stop-start) / 1024**2
print ("    Throughput:", throughput)
