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
from statistics import pstdev


def list_average(L):
  return sum(L)/len(L)


def bench_prox(n, group_name, dataset, ipescheme, iter = 1, max_t = 0, simulated = False):
  setup_time_list = []
  keygen_time_list = []
  encrypt_time_list = []
  sk_size = []
  encdb_size = []
  for i in range(iter):
    setup_a = time.time()
    database = prox_search.ProximitySearch(vector_length, ipescheme, group_name)
    setup_b = time.time()
    setup_time_list.append(setup_b-setup_a)

    keygen_a = time.time()
    database.generate_keys()
    keygen_b = time.time()
    keygen_time_list.append(keygen_b-keygen_a)

    encrypt_a = time.time()
    database.encrypt_dataset(dataset)
    encrypt_b = time.time()
    encrypt_time_list.append(encrypt_b-encrypt_a)

    sk_size.append(database.get_seckey_size())
    encdb_size.append(database.get_database_size())


 
  print("Time to setup, avg "+str(list_average(setup_time_list))+" stdev "+str(pstdev(setup_time_list)))
  print("Time to keygen, avg "+str(list_average(keygen_time_list))+" stdev "+str(pstdev(keygen_time_list)))
  print("Time to encrypt "+str(len(dataset))+" records, avg " + str(list_average(encrypt_time_list)) +
        " stdev " + str(pstdev(encrypt_time_list)))
  print("Size of secret key " + str(list_average(sk_size)) + " stdev " + str(pstdev(sk_size)))
  print("Size of encrypted data " + str(list_average(encdb_size)) + " stdev " + str(pstdev(encdb_size)))

def read_fvector(filePath):
  with open(filePath) as f:
    for line in f.readlines():
      temp_str = np.fromstring(line, sep=",")
      return [int(x) for x in temp_str]



def process_dataset():
  cwd = os.getcwd()
  feat_list = glob.glob(cwd + "//features//ND_proximity_irisR_features//*")
  f_1 = read_fvector(feat_list[0])
  cwd = os.getcwd()
  feat_list = glob.glob(cwd + "//features//IITD_proximity_irisR_features//*")
  nd_dataset = [read_fvector(x) for x in feat_list]
  iitd_dataset = [read_fvector(x) for x in feat_list]
  return (nd_dataset, iitd_dataset)


if __name__ == "__main__":
  (nd_dataset, iitd_dataset) = process_dataset()
  group_name = 'MNT159'
  vector_length = len(nd_dataset[0])
  print("Benchmarking Notre Dame")
  bench_prox(n=vector_length, group_name=group_name, dataset=nd_dataset, ipescheme=predipe.BarbosaIPEScheme, iter=10,
             max_t = 7, simulated=False)
  print("Benchmarking IITD")
  bench_prox(n=vector_length, group_name=group_name, dataset=iitd_dataset, ipescheme=predipe.BarbosaIPEScheme, iter=10,
             max_t=7, simulated=False)