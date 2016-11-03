# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from hgcrypt import common

try:
    from hgcrypt.Convergent.rabin.FastRabin import Rabin
except ImportError:
    from hgcrypt.Convergent.rabin.Rabin import Rabin
    print("Warning: Using slow Rabin implementation!")

class Convergent:
    def __init__(self, key):
        self.key = key
        self.cdata = b''
        self.obf = b''
        self.key_changed = False

    def set_cdata(self, cdata, oldkey=None):
        self.cdata = cdata
        newkey = self.key
        if oldkey is not None:
            self.key = oldkey
            self.key_changed = True
        self.load_obfuscator()
        self.key = newkey

    def load_obfuscator(self):
        iv = self.cdata[:16]
        cobf = self.cdata[16:48]
        self.obf = AES.new(self.key, AES.MODE_CBC, iv).decrypt(cobf)

    def encrypt_obfuscator(self, newiv=False):
        if newiv:
            iv = common.gen_random(16)
        else:
            iv = self.cdata[:16]
        cobf = AES.new(self.key, AES.MODE_CBC, iv).encrypt(self.obf)
        return iv + cobf

    def decrypt(self):
        # skip encrypted obfuscator
        pos = 48
        plaindata = b''
        while True:
            plainblock, pos = self.decrypt_block(pos)
            if plainblock is None:
                break
            plaindata += plainblock
        return plaindata

    def decrypt_block(self, pos):
        ckey = self.cdata[pos:pos+32]
        pos += 32
        if ckey == b'':
            return None, pos
        firstcchunk = self.cdata[pos:pos+16]
        pos += 16
        blockkey = AES.new(self.key, AES.MODE_CBC, firstcchunk).decrypt(ckey)
        iv = b''.ljust(16, b'\x00')
        cipher = AES.new(blockkey, AES.MODE_CBC, iv)
        firstpchunk = cipher.decrypt(firstcchunk)
        blocklen = common.decode_int(firstpchunk[:4])
        paddedlen = 4 + blocklen
        if paddedlen % 16 != 0:
            paddedlen += 16 - (paddedlen % 16)
        cresidual = self.cdata[pos:pos+paddedlen-16]
        pos += paddedlen-16
        pblock = firstpchunk + cipher.decrypt(cresidual)
        pblock = pblock[4:4+blocklen]
        return pblock, pos

    def encrypt(self, pdata):
        if self.obf == b'':
            self.obf = common.gen_random(32)
            cobf = self.encrypt_obfuscator(newiv=True)
        else:
            cobf = self.encrypt_obfuscator(newiv=self.key_changed)

        rab = Rabin(self.obf, avgsize=256)
        rab.set_data(pdata)

        lastpos = 0
        cipher = cobf
        while True:
            blockaddr = rab.next_block()
            if blockaddr == -1:
                break
            blocklen = blockaddr - lastpos
            pblock = pdata[lastpos:blockaddr]
            cblock = self.encrypt_block(pblock)
            cipher += cblock
            lastpos = blockaddr

        return cipher

    def encrypt_block(self, pblock):
        blocklen = len(pblock)
        block = common.encode_int(blocklen) + pblock
        blockkey = HMAC.new(self.obf, msg=block, digestmod=SHA256).digest()
        paddedlen = 4 + blocklen
        if paddedlen % 16 != 0:
            paddedlen += 16 - (paddedlen % 16)
            block = block.ljust(paddedlen, b'\x00')
        iv = b''.ljust(16, b'\x00')
        cblock = AES.new(blockkey, AES.MODE_CBC, iv).encrypt(block)
        ckey = AES.new(self.key, AES.MODE_CBC, cblock[:16]).encrypt(blockkey)
        return ckey + cblock
