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
    return sum(L) / len(L)


def get_ct_size(ct):
    ct_sizeinbytes = 0
    for elem in ct:
        elem_sizeinbytes = 0
        # extract integers from elem
        str_rep = ''.join(filter(lambda c: c == ' ' or c.isdigit(), str(elem)))
        delim_size = len(str(elem)) - len(str_rep)  # number of delimiter characters
        elem_sizeinbytes += delim_size
        L = [int(s) for s in str_rep.split()]
        for x in L:
            intsize = int(math.ceil(math.log2(x) / 8))
            elem_sizeinbytes += intsize
        ct_sizeinbytes += elem_sizeinbytes
    return ct_sizeinbytes


def bench_prox(n, group_name, dataset, ipescheme, iter=1, t=0, simulated=False):
    setup_time_list = []
    keygen_time_list = []
    encrypt_time_list = []
    sk_size = []
    encdb_size = []
    token_time_list = []
    search_time_list = []
    return_size_list = []
    for i in range(iter):
        setup_a = time.time()
        database = prox_search.ProximitySearch(vector_length, ipescheme, group_name)
        setup_b = time.time()
        setup_time_list.append(setup_b - setup_a)

        keygen_a = time.time()
        database.generate_keys()
        keygen_b = time.time()
        keygen_time_list.append(keygen_b - keygen_a)

        encrypt_a = time.time()
        database.encrypt_dataset(dataset)
        encrypt_b = time.time()
        encrypt_time_list.append(encrypt_b - encrypt_a)

        sk_size.append(database.get_seckey_size())
        encdb_size.append(database.get_database_size())
        for dataitem in dataset:
            token_a = time.time()
            token = database.generate_query(dataitem, t)
            token_b = time.time()
            token_time_list = token_b - token_a

            search_a = time.time()
            indices = database.search(token)
            search_b = time.time()
            search_time_list = search_b - search_a

            if indices is None:
                return_size_list.append(0)
            else:
                return_size_list.append(len(indices))
            #TODO: add size of token

    print("Time to setup, avg " + str(list_average(setup_time_list)) + " stdev " + str(pstdev(setup_time_list)))
    print("Time to keygen, avg " + str(list_average(keygen_time_list)) + " stdev " + str(pstdev(keygen_time_list)))
    print("Time to encrypt " + str(len(dataset)) + " records, avg " + str(list_average(encrypt_time_list)) +
          " stdev " + str(pstdev(encrypt_time_list)))
    print("Size of secret key " + str(list_average(sk_size)) + " stdev " + str(pstdev(sk_size)))
    print("Size of encrypted data " + str(list_average(encdb_size)) + " stdev " + str(pstdev(encdb_size)))
    print("Time to create token, avg " + str(list_average(token_time_list)) + " stdev " + str(pstdev(token_time_list)))
    print("Time to search, avg " + str(list_average(search_time_list)) + " stdev " + str(pstdev(search_time_list)))
    print("Number of results, avg " + str(list_average(return_size_list)) + " stdev " + str(pstdev(return_size_list)))


def accuracy_prox(n, group_name, dataset, ipescheme, iter=1, max_t=0, simulated=False):
    database = prox_search.ProximitySearch(vector_length, ipescheme, group_name)
    database.generate_keys()

    # TODO:Add accuracy testing
    # TODO: Vary t to check accuracy, need to make sure returned value is in same class.


def read_fvector(filePath):
    with open(filePath) as f:
        for line in f.readlines():
            temp_str = np.fromstring(line, sep=",")
            return [int(x) for x in temp_str]


def process_dataset():
    cwd = os.getcwd()
    feat_list = glob.glob(cwd + "//features//ND_proximity_irisR_features//*")
    nd_dataset = [read_fvector(x) for x in feat_list]
    feat_list = glob.glob(cwd + "//features//IITD_proximity_irisR_features//*")
    iitd_dataset = [read_fvector(x) for x in feat_list]

    return nd_dataset, iitd_dataset


if __name__ == "__main__":
    (nd_dataset, iitd_dataset) = process_dataset()
    group_name = 'MNT159'
    vector_length = len(nd_dataset[0])
    print("Benchmarking Notre Dame")
    bench_prox(n=vector_length, group_name=group_name, dataset=nd_dataset, ipescheme=predipe.BarbosaIPEScheme, iter=1,
               t=8, simulated=False)
    print("Benchmarking IITD")
    bench_prox(n=vector_length, group_name=group_name, dataset=iitd_dataset, ipescheme=predipe.BarbosaIPEScheme,
               iter=1, t=17, simulated=False)
