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

import sys, os, math, random, time, zlib, subprocess

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from subprocess import call, Popen, PIPE
from fhipe import ipe

class MultiBasisPredIPEScheme():
    def __init__(self, n, group_name = 'MNT159', sigma=1, simulated = False):
        pass

    def encrypt(self, x):
        pass

    def keygen(self, y):
        pass

    @staticmethod
    def decrypt(self, public_params, ct, token) -> bool:
        pass

    def getPublicParameters(self):
        pass

class BarbosaIPEScheme(MultiBasisPredIPEScheme):

    def __init__(self, n, group_name = 'MNT159', sigma=1, simulated = False):
        """
        Performs the setup algorithm for IPE.

        This function samples the generators from the group, specified optionally by
        "group_name". This variable must be one of a few set of strings specified by
        Charm.

        Then, it invokes the C program ./gen_matrices, which samples random matrices
        and outputs them back to this function. The dimension n is supplied, and the
        prime is chosen as the order of the group. Additionally, /dev/urandom is
        sampled for a random seed which is passed to ./gen_matrices.

        Finally, the function constructs the matrices that form the secret key and
        publishes the public parameters and secret key (pp, sk).
        """

        assert (float(sigma).is_integer()), "ERROR: Sigma must be an integer."
        assert (sigma > 0), "ERROR: Sigma must be greater than zero."
        assert (sigma < n), "ERROR: Sigma must be lesser or equal to n."
        assert (n % sigma == 0), "ERROR: Sigma must divide n."

        self.sigma = sigma
        self.B = list()
        self.Bstar = list()

        group = PairingGroup(group_name)
        g1 = group.random(G1)
        g2 = group.random(G2)
        assert g1.initPP(), "ERROR: Failed to init pre-computation table for g1."
        assert g2.initPP(), "ERROR: Failed to init pre-computation table for g2."

        for i in range(self.sigma):
            proc = Popen(
              [
                os.path.dirname(os.path.realpath(__file__)) + '/gen_matrices',
                str(n/self.sigma + 1),
                str(group.order()),
                "1" if simulated else "0",
                ""
              ],
              stdout=PIPE
            )

            detB_str = proc.stdout.readline().decode()
            B_str = proc.stdout.readline().decode()
            Bstar_str = proc.stdout.readline().decode()

            detB = int(detB_str)
            B = ipe.parse_matrix(B_str, group)
            Bstar = ipe.parse_matrix(Bstar_str, group)

            self.B.append(B)
            self.Bstar.append(Bstar)

        pp = [G1, G2, GT, "q", "e", n, self.sigma]

        self.group = group
        self.g1 = g1
        self.g2 = g2
        self.public_parameters = pp

    def encrypt(self, x):
        n = len(x)
        beta = self.group.random(ZR)
        ct = list()

        # prepare secret sharing of zero
        zeta = list()
        zeta_sigma = 0

        for l in range(self.sigma - 1):
            zeta.append(self.group.random(ZR))
            zeta_sigma += zeta[l]
        zeta.append(zeta_sigma * (-1))

        for l in range(self.sigma):

            c = [0] * int(n/self.sigma + 1)

            for j in range(int(n/self.sigma + 1)):
                sum = 0
                for i in range(int(n/self.sigma)):
                    sum += x[l*int(n/self.sigma)+i] * self.Bstar[l][i][j]

                sum += zeta[l] * self.Bstar[l][self.sigma][j]
                c[j] = beta * sum

            for i in range(int(n/self.sigma + 1)):
              c[i] = self.g2 ** c[i]

            ct.append(c)
        print(ct)
        return ct

    def keygen(self, y):
        """
        Performs the keygen algorithm for IPE.
        """

        n = len(y)
        alpha = self.group.random(ZR)
        tk = list()

        for l in range(self.sigma):

            k = [0] * int(n/self.sigma + 1)

            for j in range(int(n/self.sigma + 1)):
                sum = 0
                for i in range(int(n/self.sigma)):
                    sum += y[l*int(n/self.sigma)+i] * self.B[l][i][j]

                sum += self.B[l][self.sigma][j]
                k[j] = alpha * sum

            for i in range(int(n/self.sigma + 1)):
              k[i] = self.g1 ** k[i]

            tk.append(k)

        print(tk)
        return tk

    def getPublicParameters(self):
        return self.public_parameters

    @staticmethod
    def decrypt(public_params, ct, tk, group_name='MNT159') -> bool:
        """
        Performs the decrypt algorithm for IPE on a secret key skx and ciphertext cty.
        The output is the inner product <x,y>, so long as it is in the range
        [0,max_innerprod].
        """
        sigma = public_params[6]

        group = PairingGroup(group_name)
        identity = group.random(GT) ** 0

        result = identity

        for l in range(sigma):
            result = result * ipe.innerprod_pair(ct[l], tk[l])

        return result == identity


