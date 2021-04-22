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
from fhipe import ipe
from fhipe.predipe import PredIPEScheme
from fhipe.predipe import BarbosaIPEScheme
from charm.core.engine.util import objectToBytes,bytesToObject

class MultiBasesPredScheme(PredIPEScheme):

    def __init__(self, n, group_name = 'MNT159', num_bases = 1, simulated = False):
        group = PairingGroup(group_name)
        self.group = group
        self.group_name = group_name
        self.vector_length = n
        self.simulated = simulated
        self.g1 = None
        self.g2 = None
        self.num_bases = num_bases
        assert (float(num_bases).is_integer()), "ERROR: Sigma must be an integer."
        assert (num_bases > 0), "ERROR: Sigma must be greater than zero."
        assert (num_bases <= n), "ERROR: Sigma must be lesser or equal to n."
        #Revisist whether sigma has to divide n
        assert (n % num_bases == 0), "ERROR: Sigma must divide n."
        self.component_length = ceil(self.vector_length/self.num_bases)+1
        self.barbosa_vec=[]


    def generate_keys(self):
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

        self.barbosa_vec=[]

        for i in range(self.num_bases):
            (B, Bstar, pp) = BarbosaIPEScheme.generate_matrices(self.component_length, self.simulated, self.group)
            b_instance = BarbosaIPEScheme(self.component_length, self.group_name, self.simulated)
            b_instance.set_key(B, Bstar, pp, self.g1, self.g2)
            self.barbosa_vec.append(b_instance)

    def encrypt(self, x):
        assert(len(x) == self.vector_length)
        n = self.vector_length
        # prepare secret sharing of zero
        zeta = []
        zeta_sigma = self.group.init(ZR, 0)

        for l in range(self.num_bases - 1):
            zeta.append(self.group.random(ZR))
            zeta_sigma += zeta[l]
        zeta.append(zeta_sigma * (-1))
        zeta_sum = self.group.init(ZR, 0)
        for z in zeta:
            zeta_sum+=z
        assert(zeta_sum == self.group.init(ZR, 0))

        c = []
        for l in range(self.num_bases):

            x_modified = [0] * self.component_length
            for j in range(self.component_length-1):
                x_modified[j] = x[l*int(n/self.num_bases)+j]
#            x_modified[self.component_length-1]= zeta[l]
            x_modified[self.component_length-1]= 0
            print("Modified x "+str(x_modified))
            c.append(self.barbosa_vec[l].encrypt(x_modified))
        return c

    def keygen(self, y):
        """
        Performs the keygen algorithm for IPE.
        """
        assert(len(y) == self.vector_length)
        n = self.vector_length
        tk= []
        for l in range(self.num_bases):

            y_modified = [0] * self.component_length
            for j in range(self.component_length-1):
                y_modified[j] = y[l*int(n/self.num_bases)+j]
            y_modified[self.component_length-1]= 1
            print("Modified y "+str(y_modified))
            tk.append(self.barbosa_vec[l].keygen(y_modified))
        return tk

    def getPublicParameters(self):
        a =[]
        for x in self.barbosa_vec:
            a.append(x.getPublicParameters())
        return a

    @staticmethod
    def decrypt(public_params, ct, tk, group_name='MNT159') -> bool:
        """
        Performs the decrypt algorithm for IPE on a secret key skx and ciphertext cty.
        The output is the inner product <x,y>, so long as it is in the range
        [0,max_innerprod].
        """
        ct_flat =  [item for subl in ct for item in subl]
        print(ct_flat)
        tk_flat =  [item for subl in tk for item in subl]
        print(tk_flat)
        return BarbosaIPEScheme.decrypt(public_params[0], ct_flat,tk_flat)


