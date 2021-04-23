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
Obtains micro-benchmarks for the running times and parameter sizes of IPE and 
two-input functional encryption.
"""

# Path hack.
import sys, os, math, glob, numpy as np
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))

import random, time, zlib
from fhipe import predipe, prox_search, multibasispredipe

def list_tuple_mean(L):
  avgs = [0] * len(L[0])
  for tup in L:
    for i in range(len(tup)):
      avgs[i] += tup[i]
  for i in range(len(avgs)):
    avgs[i] /= len(L)
  return avgs

def bench_prox(n, group_name, iter = 10, simulated = False):
  setup_a = time.time()
  (pp, sk) = ipe.setup(n, group_name, simulated)
  setup_b = time.time()


 
  L = []
  for index in range(iter):
    x = [random.randint(0, M) for i in range(n)]
    y = [random.randint(0, M) for i in range(n)]
   
    keygen_a = time.time()
    skx = ipe.keygen(sk, x)
    keygen_b = time.time()
    
    encrypt_a = time.time()
    cty = ipe.encrypt(sk, y)
    encrypt_b = time.time()

    ctsize = get_ct_size(cty)

    decrypt_a = time.time()
    prod = ipe.decrypt(pp, skx, cty, M*M*n)
    decrypt_b = time.time()

    L.append((keygen_b - keygen_a, encrypt_b - encrypt_a, decrypt_b - decrypt_a, 
        ctsize))
  print("raw runtimes for each iteration: ", L)

  return (setup_b - setup_a, list_tuple_mean(L))

def read_fvector(filePath):
  with open(filePath) as f:
    for line in f.readlines():
      return np.fromstring(line, sep=",")



def process_dataset():
  cwd = os.getcwd()
  feat_list = glob.glob(cwd + "//features//ND_proximity_irisR_features//*")
  f_1 = read_fvector(feat_list[0])

  print("Notre Dame 0405:")
  print ("Number of features: " + str(len(feat_list)))

  print ("Vector dimensions: " + str(len(f_1)))

  print ("Example feature vector: " + str(f_1))

  cwd = os.getcwd()
  feat_list = glob.glob(cwd + "//features//IITD_proximity_irisR_features//*")
  f_1 = read_fvector(feat_list[0])
  print("IITD:")

  print ("Number of features: " + str(len(feat_list)))

  print ("Vector dimensions: " + str(len(f_1)))

  print ("Example feature vector: " + str(f_1))


if __name__ == "__main__":
  process_dataset()
