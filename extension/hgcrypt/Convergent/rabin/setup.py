# Copyright 2013-2016 Michael Lass <bevan@bi-co.net>
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2 or any later version.

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [Extension("FastRabin", ["FastRabin.pyx"])]

setup(
  name = 'Fast implementation of Rabin fingerprints',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules
)
