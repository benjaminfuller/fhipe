"""
Copyright (c) 2016, Kevin Lewi
 
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""


"""
Implementation of function-hiding inner product encryption (FHIPE).
"""

import sys, os, math, random, time, zlib
from math import ceil

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from subprocess import call, Popen, PIPE
from fhipe import ipe
from fhipe.predipe import PredIPEScheme
from fhipe.predipe import BarbosaIPEScheme
from charm.core.engine.util import objectToBytes,bytesToObject

class MultiBasesPredScheme(PredIPEScheme):

    def __init__(self, n, group_name = 'MNT159', num_bases = 1, simulated = False):
        group = PairingGroup(group_name)
        self.group = group
        self.vector_length = n
        self.simulated = simulated
        self.g1 = None
        self.g2 = None
        self.num_bases = num_bases
        self.component_length = ceil(self.vector_length/self.num_bases)+1


    def generate_keys(self):
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        Bvec = []
        Bstarvec = []
        ppvec = []
        for i in range(self.num_bases):
            (B, Bstar, pp) = BarbosaIPEScheme.generate_matrices(self.component_length, self.simulated, self.group)
            Bvec.append(B)
            Bstarvec.append(Bstar)
            ppvec.append(pp)

    def encrypt(self, x):
        psivec = []
        lastpsi = 0
        for i in range(self.num_bases-1):
            psi_i =  self.group.random(ZR)
            psivec.append(psi_i)
            lastpsi-=psi_i
        psivec.append(lastpsi)
        #Secret share 0 for vector
        share  = self.group.init(ZR, 0)
        for i in psivec:
            share+=i

        componentxvec = []
        start =0
        end = 0
        for i in range(self.num_bases):
            print("Hello")

        print(componentxvec)
        pass

    def keygen(self, y):
        pass

    @staticmethod
    def decrypt(self, public_params, ct, token) -> bool:
        pass

    def getPublicParameters(self):
        pass



