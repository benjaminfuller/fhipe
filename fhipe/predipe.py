"""
Copyright (c) 2021, Benjamin Fuller
 
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
Implementation of Barbosa et al. CT RSA Predicate IPE Scheme
"""

import sys, os, math, random, time, zlib, secrets

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from subprocess import call, Popen, PIPE
from fhipe import ipe
from charm.core.engine.util import objectToBytes,bytesToObject

class PredIPEScheme():
    def __init__(self, n, group_name = 'MNT159', simulated = False):
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

class BarbosaIPEScheme(PredIPEScheme):

    def __init__(self,n, group_name = 'MNT159', simulated = False):
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
        group = PairingGroup(group_name)
        self.group = group
        self.vector_length = n
        self.simulated = simulated
        self.g1 = None
        self.g2 = None
        self.B= None
        self.Bstar = None
        self.public_parameters = None

    @staticmethod
    def generate_matrices(vector_length, simulated, group):
        if not simulated:
            matrix_seed = secrets.token_bytes(128)
        else:
            matrix_seed=""
        proc = Popen(
            [
                os.path.dirname(os.path.realpath(__file__)) + '/gen_matrices',
                str(vector_length),
                str(group.order()),
                "1" if simulated else "0",
                str(matrix_seed)
            ],
            stdout=PIPE
        )
        _ = proc.stdout.readline().decode()
        B_str = proc.stdout.readline().decode()
        Bstar_str = proc.stdout.readline().decode()
        B = ipe.parse_matrix(B_str, group)
        Bstar = ipe.parse_matrix(Bstar_str, group)

        pp = ()
        return B, Bstar, pp

    def set_key(self, B, Bstar, pp, g1, g2):
        self.B = B
        self.Bstar = Bstar
        self.public_parameters = pp
        self.g1 = g1
        self.g2 = g2

    def generate_keys(self):
        (self.B, self.Bstar, self.public_parameters) =self.generate_matrices(self.vector_length, self.simulated, self.group)
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

    def serialize_matrices(self, matrix_filename):
        # This has the effect of putting two spaces after the dimensions.  This is to be consistent
        # with what flint is doing as we're generating matrices from flint in other places
        result_str = str(self.vector_length) + " " + str(self.vector_length) + " "
        for x in self.B:
            for y in x:
                result_str = result_str + " " + str(y)
        result_str = result_str + "\n" + str(self.vector_length) + " " + str(self.vector_length) + " "
        for x in self.Bstar:
            for y in x:
                result_str = result_str + " " + str(y)

        with open(matrix_filename, "a") as secret_key_file:
            secret_key_file.write(result_str)
            secret_key_file.close()

    def serialize_key(self, matrix_filename, generator_filename):
        open(matrix_filename, 'w').close()

        self.serialize_matrices(matrix_filename)


        g1bytes = objectToBytes(self.g1, self.group)
        g2bytes = objectToBytes(self.g2, self.group)

        result_str= "\n"+str(len(g1bytes))+" "+str(len(g2bytes))
        with open(matrix_filename, "a") as secret_key_file:
            secret_key_file.write(result_str)
            secret_key_file.close()

        with open(generator_filename, "wb") as secret_key_file:
            secret_key_file.write(g1bytes)
            secret_key_file.write(g2bytes)
            secret_key_file.close()


    def deserialize_key(self, matrix_filename, generator_filename):
        matrix_contents=""
        with open(matrix_filename, "r") as secret_key_file:
            matrix_contents = secret_key_file.read()
            secret_key_file.close()

        (Bstr, Bstarstr, gparams) = str.split(matrix_contents, '\n')
        B = ipe.parse_matrix(Bstr, self.group)
        Bstar = ipe.parse_matrix(Bstarstr, self.group)


        (g1len, g2len) = str.split(gparams, ' ')
        with open(generator_filename, "rb") as secret_key_file:
            g1bytes = secret_key_file.read(int(g1len))
            g2bytes = secret_key_file.read(int(g2len))
        self.g1 = bytesToObject(g1bytes, self.group)
        self.g2 = bytesToObject(g2bytes, self.group)

        pp = ()
        self.B = B
        self.Bstar = Bstar
        self.public_parameters = pp

        assert self.g1.initPP(), "ERROR: Failed to init pre-computation table for g1."
        assert self.g2.initPP(), "ERROR: Failed to init pre-computation table for g2."

    def fake_encrypt(self, x, beta=None):
        if not beta:
            beta = self.group.random(ZR)
        n = len(x)

        c = [0] * n
        for j in range(n):
            sum = 0
            for i in range(n):
                sum += x[i] * self.Bstar[i][j]
            c[j] = beta * sum
        return c

    def encrypt(self, x, beta=None):
        if not beta:
            beta = self.group.random(ZR)
        n = len(x)

        c = [0] * n
        for j in range(n):
            sum = 0
            for i in range(n):
                sum += x[i] * self.Bstar[i][j]
            c[j] = beta * sum

        for i in range(n):
           c[i] = self.g2 ** c[i]
        return c

    def fake_keygen(self, y, alpha=None):
        if not alpha:
            alpha = self.group.random(ZR)
        n = len(y)

        k = [0] * n
        for j in range(n):
            sum = 0
            for i in range(n):
                sum += y[i] * self.B[i][j]
            k[j] = alpha * sum
        return k
    def keygen(self, y, alpha=None):
        if not alpha:
            alpha = self.group.random(ZR)
        n = len(y)

        k = [0] * n
        for j in range(n):
            sum = 0
            for i in range(n):
                sum += y[i] * self.B[i][j]
            k[j] = alpha * sum

        for i in range(n):
            k[i] = self.g1 ** k[i]
        return k



    def getPublicParameters(self):
        return self.public_parameters

    @staticmethod
    def decrypt(public_params, ct, token, group_name='MNT159') -> bool:
        """
        Performs the decrypt algorithm for IPE on a secret key skx and ciphertext cty.
        The output is the inner product <x,y>, so long as it is in the range
        [0,max_innerprod].
        """

        result = ipe.innerprod_pair(ct, token)
        return result == PairingGroup(group_name).init(GT,1)




