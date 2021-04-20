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

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from subprocess import call, Popen, PIPE
from ipe import innerprod_pair, parse_matrix


def PredSetup(n, group_name = 'MNT159', simulated = False):
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
    g1 = group.random(G1)
    g2 = group.random(G2)
    assert g1.initPP(), "ERROR: Failed to init pre-computation table for g1."
    assert g2.initPP(), "ERROR: Failed to init pre-computation table for g2."
  
    proc = Popen(
      [
        os.path.dirname(os.path.realpath(__file__)) + '/gen_matrices',
        str(n),
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
    B = parse_matrix(B_str, group)
    Bstar = parse_matrix(Bstar_str, group)

    pp = ()
    sk = (detB, B, Bstar, group, g1, g2)
    return (pp, sk)

def PredKeygen(sk, x):
    """
    Performs the keygen algorithm for IPE.
    """

    (detB, B, Bstar, group, g1, g2) = sk
    n = len(x)
    alpha = group.random(ZR)

    k1 = [0] * n
    for j in range(n):
      sum = 0
      for i in range(n):
        sum += x[i] * B[i][j]
      k1[j] = alpha * sum

    for i in range(n):
      k1[i] = g1 ** k1[i]


    return k1

def PredEncrypt(sk, x):
    """
    Performs the encrypt algorithm for IPE.
    """

    (detB, B, Bstar, group, g1, g2) = sk
    n = len(x)
    beta = group.random(ZR)

    c1 = [0] * n
    for j in range(n):
      sum = 0
      for i in range(n):
        sum += x[i] * Bstar[i][j]
      c1[j] = beta * sum

    for i in range(n):
      c1[i] = g2 ** c1[i]

    return c1

def PredDecrypt(pp, skx, cty):
    """
    Performs the decrypt algorithm for IPE on a secret key skx and ciphertext cty.
    The output is the inner product <x,y>, so long as it is in the range
    [0,max_innerprod].
    """

    result = innerprod_pair(skx, cty)
  #  print(result)
    group = PairingGroup(group_name)
    identity = group.random(GT) ** 0
    return (result == identity)



n=4
group_name='MNT159'
(pp, sk) = PredSetup(n, group_name)
#print(sk)
x=(1, -1, -1, 1)
ctx = PredEncrypt(sk, x)
y=(1, 1, 1, 1)
tky = PredKeygen(sk, y)
print(PredDecrypt(pp, tky, ctx))



