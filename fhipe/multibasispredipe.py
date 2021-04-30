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

import sys, os, math, random, time, zlib, asyncio
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

    def __init__(self, n, group_name='MNT159', simulated=False, num_bases=1):
        group = PairingGroup(group_name)
        self.group = group
        self.group_name = group_name
        self.vector_length = n
        self.simulated = simulated
        self.g1 = None
        self.g2 = None

        self.component_length = 0
        self.num_bases = 0
        self.set_number_bases(num_bases)
        self.barbosa_vec = []

    def set_number_bases(self, num_bases):
        assert (float(num_bases).is_integer()), "ERROR: Sigma must be an integer."
        assert (num_bases > 0), "ERROR: Sigma must be greater than zero."
        assert (num_bases <= self.vector_length), "ERROR: Sigma must be lesser or equal to n."
        self.num_bases = num_bases
        self.component_length = ceil(self.vector_length / self.num_bases) + 1

    async def __generate_matrix_pair(self, i):
        print("starting basis " + str(i) + "generation ...")
        b_instance = BarbosaIPEScheme(self.component_length, self.group_name, self.simulated)
        (B, Bstar, pp, detB) = BarbosaIPEScheme.generate_matrices(self.component_length, self.simulated, self.group)

        # divide Bstar by detB inverse to have Bstar * B = I
        for j in range(int(self.component_length)):
            for k in range(int(self.component_length)):
                Bstar[j][k] = Bstar[j][k] * (1 / detB)

        b_instance.set_key(B, Bstar, pp, self.g1, self.g2)
        self.barbosa_vec.append(b_instance)

        delay = random.randint(1,10)
        await asyncio.sleep(delay)
        print("end of basis " + str(i) + "generation.")


    async def generate_keys_parallel(self):
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.barbosa_vec = []

        taskvec = []
        for i in range(self.num_bases):
            taskvec.append(asyncio.create_task(self.__generate_matrix_pair(i)))

        await asyncio.gather(*taskvec)

        for i in range(self.num_bases):
            print(i)
            print(self.barbosa_vec[i].print_key())



    def generate_keys(self):
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.barbosa_vec = []

        for i in range(self.num_bases):
            b_instance = BarbosaIPEScheme(self.component_length, self.group_name, self.simulated)
            (B, Bstar, pp, detB) = BarbosaIPEScheme.generate_matrices(self.component_length, self.simulated, self.group)

            # divide Bstar by detB inverse to have Bstar * B = I
            for j in range(int(self.component_length)):
                for k in range(int(self.component_length)):
                    Bstar[j][k] = Bstar[j][k] * (1/detB)

            b_instance.set_key(B, Bstar, pp, self.g1, self.g2)
            self.barbosa_vec.append(b_instance)
            # print("Basis " + str(i) + " : ")
            # print(self.barbosa_vec[i].print_key())

    def serialize_key(self, matrix_filename, generator_filename):
        i = 0
        for binstance in self.barbosa_vec:
            binstance.serialize_key(matrix_filename, generator_filename)
            i = i+1

    def encrypt(self, x):
        print("Calling encrypt " + str(x))
        assert(len(x) == self.vector_length)
        n = self.vector_length

        # prepare secret sharing of zero
        zeta = []
        zeta_sigma = self.group.init(ZR, 0)

        for i in range(self.num_bases - 1):
            zeta.append(self.group.random(ZR))
            zeta_sigma += zeta[i]
        zeta.append(zeta_sigma * (-1))
        zeta_sum = self.group.init(ZR, 0)

        for z in zeta:
            zeta_sum += z
        assert(zeta_sum == self.group.init(ZR, 0))

        c = []
        beta = self.group.random(ZR)
        for i in range(self.num_bases):

            x_modified = [0] * self.component_length
            for j in range(self.component_length-1):

                if i*ceil(n/self.num_bases) + j < len(x):
                    x_modified[j] = x[i*ceil(n/self.num_bases)+j]
                else:
                    x_modified[j] = 0

            x_modified[self.component_length-1] = zeta[i]
            c.append(self.barbosa_vec[i].encrypt(x_modified, beta))
        return c

    def keygen(self, y):
        """
        Performs the keygen algorithm for IPE.
        """
        print("Calling Key gen "+str(y))
        assert(len(y) == self.vector_length)
        n = self.vector_length
        tk = []

        alpha = self.group.random(ZR)
        for i in range(self.num_bases):

            y_modified = [0] * self.component_length
            for j in range(self.component_length-1):

                if i*ceil(n/self.num_bases) + j < len(y):
                    y_modified[j] = y[i*ceil(n/self.num_bases)+j]
                else:
                    y_modified[j] = 0

            y_modified[self.component_length-1] = -1
            tk.append(self.barbosa_vec[i].keygen(y_modified, alpha))

        return tk

    def getPublicParameters(self):
        a = []
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
        ct_flat = [item for subl in ct for item in subl]
        tk_flat = [item for subl in tk for item in subl]
        return BarbosaIPEScheme.decrypt(public_params[0], ct_flat, tk_flat)

