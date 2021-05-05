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
import sys, os, math, glob, numpy as np, argparse, asyncio

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


def bench_keygen(n, group_name, ipescheme, iter=1, matrix_file=None, gen_file=None, simulated=False,
                 save_keys=False, num_bases=1):
    setup_time_list = []
    keygen_time_list = []
    database_size = []
    database = None
    for i in range(iter):
        setup_a = time.time()
        database = prox_search.ProximitySearch(n, ipescheme, group_name)
        setup_b = time.time()
        setup_time_list.append(setup_b - setup_a)
        if ipescheme is multibasispredipe.MultiBasesPredScheme and num_bases > 1:
            database.predinstance.set_number_bases(num_bases)
        keygen_a = time.time()
        database.generate_keys()
        keygen_b = time.time()
        keygen_time_list.append(keygen_b - keygen_a)

        if matrix_file is not None and gen_file is not None:
            database.serialize_key(matrix_file, gen_file)
            if ipescheme is predipe.BarbosaIPEScheme:
                database_size.append(
                    int(os.path.getsize(matrix_file)) + int(os.path.getsize(gen_file)))
            else:
                size = int(os.path.getsize(gen_file))
                for j in range(num_bases):
                    size = size+os.path.getsize(matrix_file+str(j))
                database_size.append(size)

    print(str(num_bases)+", "+str(list_average(setup_time_list))+", "+str(pstdev(setup_time_list)) +
          ", " + str(list_average(keygen_time_list))+", " + str(pstdev(keygen_time_list)) +
          ", " + str(list_average(database_size))+", "+str(pstdev(database_size)))
    if matrix_file is not None and gen_file is not None and save_keys:
        database.serialize_key(matrix_file, gen_file)
    return database


def bench_enc_data(n, database, dataset, iter=1, parallel=0):
    encdb_size = []
    encrypt_time_list = []
    num_bases = 1
    if database is multibasispredipe.MultiBasesPredScheme:
        num_bases = database.predinstance.num_bases
    for i in range(iter):
        encrypt_a = time.time()
        if parallel is 1:
            database.encrypt_dataset_parallel(dataset)
        else:
            database.encrypt_dataset(dataset)
        encrypt_b = time.time()
        encrypt_time_list.append(encrypt_b - encrypt_a)
        encdb_size.append(database.get_database_size())
    print(str(num_bases)+", "+str(parallel)+", "+str(list_average(encrypt_time_list))+", "+
          str(pstdev(encrypt_time_list))+", "+str(list_average(encdb_size))+", "+str(pstdev(encdb_size)))

def bench_queries(n, database, queryset, iter=1, t=0, parallel=0):
    sk_size = []
    token_time_list = []
    search_time_list = []
    parallel_search_time_list = []
    return_size_list = []
    for i in range(iter):
        sk_size.append(database.get_seckey_size())
        j = 0
        for dataitem in queryset:
            token_a = time.time()
            token =  database.generate_query(dataitem, t)
            token_b = time.time()
            token_time_list.append(token_b - token_a)

            search_a = time.time()
            if parallel is 1:
                indices =database.parallel_search(token)
            else:
                indices = database.search(token)
            search_b = time.time()
            print(indices)
            parallel_search_time_list.append(search_b - search_a)

            # search_a = time.time()
            # indices = database.search(token)
            # search_b = time.time()
            # search_time_list.append(search_b - search_a)


            if indices is None:
                return_size_list.append(0)
            else:
                return_size_list.append(len(indices))
                print("Matches for query " + str(i) + " " + str(len(indices)))
            # TODO: add size of token

            j = j + 1

    print(str(list_average(sk_size)) + ", " + str(pstdev(sk_size))+", "+str(list_average(token_time_list)) + ", "+
          str(pstdev(token_time_list)) + ", " + str(list_average(parallel_search_time_list)) + ", "+
          str(pstdev(parallel_search_time_list)) + ", "+str(list_average(return_size_list))+ ", "+
          str(pstdev(return_size_list)))

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
    parser = argparse.ArgumentParser(description='Benchmarking of Proximity Search Schemes.')
    parser.add_argument('--matrix_file', '-mf', nargs='*', help='The file for the matrices')
    parser.add_argument('--generator_file', '-gf', nargs='*', help='The file for the group generators')
    parser.add_argument('--save', '-s', const=1, type=int, nargs='?', default=0,
                        help='Write a secret key to file and quit')
    parser.add_argument('--load', '-l', const=1, type=int, nargs='?', default=0,
                        help='Load Secret Key from File')
    parser.add_argument('--benchmark_queries', '-bq', const=1, type=int, nargs='?',
                        default=0, help='Benchmark Query Time and Accuracy')
    parser.add_argument('--benchmark_key_gen', '-bk', const=1, type=int, nargs='?',
                        default=0, help='Benchmark Key Generation')
    parser.add_argument('--benchmark_enc', '-be', const=1, type=int, nargs='?',
                        default=0, help='Benchmark Dataset encryption')
    parser.add_argument('--parallel', '-p', const=1, type=int, nargs='?',
                        default=0, help='Whether to run parallel algorithms, default yes')
    args = vars(parser.parse_args())

    matrix_file = None
    gen_file = None

    (nd_dataset, iitd_dataset) = process_dataset()
    group_name = 'MNT159'
    vector_length = len(nd_dataset[0])

    if args['matrix_file'] and args['generator_file']:
        matrix_file = args['matrix_file'][0]
        gen_file = args['generator_file'][0]

    save = False
    database = None
    parallel = args['parallel']
    if args['save']:
        save = True
    if args['benchmark_key_gen']:
        print("Benchmarking Multi Basis Generation")
        print("Number Bases, Setup Time Av, Setup Time STDev, KeyGen Time Avg, KeyGen Time STDEv, Key size Avg, "
              "Key Size STDev")
        for i in range(65):
            database = bench_keygen(n=vector_length, group_name=group_name,
                                    ipescheme=multibasispredipe.MultiBasesPredScheme, iter=1,
                                    matrix_file=matrix_file, gen_file=gen_file, save_keys=save, num_bases=65 - i)

        print("Benchmarking Barbosa Key Generation")
        database = bench_keygen(n=vector_length, group_name=group_name,
                                ipescheme=predipe.BarbosaIPEScheme, iter=10,
                                matrix_file=matrix_file, gen_file=gen_file, save_keys=save, num_bases=1)

    if args['load'] and args['matrix_file'] and args['generator_file']:
        database = prox_search.ProximitySearch(vector_length, predipe.BarbosaIPEScheme, group_name)
        database.deserialize_key(matrix_file, gen_file)
    if args['benchmark_enc']:
        if database is None:
            database = prox_search.ProximitySearch(vector_length, predipe.BarbosaIPEScheme, group_name)
            database.generate_keys()
        print("Benchmarking Barbosa Encryption")
        print("Number Bases, Parallel, Time Avg, Time StDev, Size Avg, Size StDev")
        bench_enc_data(n=vector_length, database=database, dataset=nd_dataset, iter=1, parallel=parallel)

    if args['benchmark_queries']:
        if database is None:
            database = prox_search.ProximitySearch(vector_length, predipe.BarbosaIPEScheme, group_name)
            database.generate_keys()
            database.enc_data(nd_dataset)
        print("Benchmarking Query Time")
        print("SK size Avg, SK size STDev, Token time avg, Token time STDev, Search time Avg, Search time STDev,"
              " Num Results Avg, STDev")
        bench_queries(n=vector_length, database=database, queryset=nd_dataset[:1], iter=1, t=8, parallel=parallel)
