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


def bench_keygen(n, group_name, ipescheme, iterations=1, matrix_file=None, gen_file=None, simulated=False,
                 save_keys=False, num_bases=1):
    setup_time_list = []
    keygen_time_list = []
    database_size = []
    database = None
    for i in range(iterations):
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
        database_size.append(database.get_seckey_size())

    print(str(num_bases)+", "+str(list_average(setup_time_list))+", "+str(pstdev(setup_time_list)) +
          ", " + str(list_average(keygen_time_list))+", " + str(pstdev(keygen_time_list)) +
          ", " + str(list_average(database_size))+", "+str(pstdev(database_size)))
    if matrix_file is not None and gen_file is not None and save_keys:
        if ipescheme is predipe.BarbosaIPEScheme:
            database.write_key_to_file(matrix_file, gen_file)
        else:
            database.write_key_to_file(matrix_file+str(num_bases), gen_file+str(num_bases))
    return database


def bench_enc_data(n, database, dataset, iterations=1, parallel=0):
    encdb_size = []
    encrypt_time_list = []
    num_bases = 1
    if database.predicate_scheme is multibasispredipe.MultiBasesPredScheme:
        num_bases = database.predinstance.num_bases
    for i in range(iterations):
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

def bench_queries(n, database, queryset, iterations=1, t=0, parallel=0):
    sk_size = []
    token_time_list = []
    search_time_list = []
    parallel_search_time_list = []
    return_size_list = []
    true_accept_rate = 0
    false_accept_rate = 0
    for i in range(iterations):
        query_class = random.randrange(0,len(queryset))
        query_choice = random.randrange(1,len(queryset[query_class]))
        dataitem = queryset[query_class][query_choice]
        token_a = time.time()
        token = database.generate_query(dataitem, t)
        token_b = time.time()
        token_time_list.append(token_b - token_a)

        search_a = time.time()
        if parallel is 1:
            indices =database.parallel_search(token)
        else:
            indices = database.search(token)
        if str(query_class) in indices:
            true_accept_rate = true_accept_rate + 1 / iterations
            if len(indices) > 1:
                false_accept_rate = false_accept_rate + 1 / iterations
        elif len(indices) > 0:
            false_accept_rate = false_accept_rate + 1 / iterations
        search_b = time.time()
        parallel_search_time_list.append(search_b - search_a)

    print(str(list_average(token_time_list)) + ", "+
          str(pstdev(token_time_list)) + ", " + str(list_average(parallel_search_time_list)) + ", "+
          str(pstdev(parallel_search_time_list))+", "+str(true_accept_rate)+", "+str(false_accept_rate))

def bench_accuracy(n, database, queryset, iterations=1, t=0, parallel=0):
    true_accept_rate = 0
    false_accept_rate = 0
    dataset_size = sum(len(queryset[query_class]) for query_class in queryset)
    total_queries = iterations*dataset_size
    for i in range(iterations):
        for query_class in queryset:
            for dataitem in queryset[query_class]:
                token = database.generate_query(dataitem, t)
                if parallel is 1:
                    indices = database.parallel_search(token)
                else:
                    indices = database.search(token)
                print("Indices "+str(indices))
                print(dataitem)
                print(queryset[query_class][0])
                if str(query_class) in indices:
                    true_accept_rate = true_accept_rate + 1 / total_queries
                    if len(indices) > 1:
                        false_accept_rate = false_accept_rate + 1 / total_queries
                elif len(indices) > 0:
                    false_accept_rate = false_accept_rate + 1 / total_queries
    print(str(true_accept_rate) + ", " + str(false_accept_rate))

def read_fvector(filePath):
    with open(filePath) as f:
        for line in f.readlines():
            temp_str = np.fromstring(line, sep=",")
            return [int(x) for x in temp_str]


def process_full_dataset():
    cwd = os.getcwd()
    dir_list = glob.glob(cwd + "//features//ND_proximity_irisR_all_features_folders//*")
    nd_dataset={}
    class_labels={}
    i=0
    for dir in dir_list:
        feat_list = glob.glob(dir+"//*")
        nd_dataset[i] = [read_fvector(x) for x in feat_list]
        class_labels[i] = dir
        i = i+1
    nd_templates = [nd_dataset[x][0] for x in nd_dataset]
    return (nd_dataset, nd_templates, class_labels)

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
    parser.add_argument('--benchmark_accuracy', '-ba', const=1, type=int, nargs='?',
                        default=0, help='Benchmark Accuracy')
    parser.add_argument('--parallel', '-p', const=1, type=int, nargs='?',
                        default=0, help='Whether to run parallel algorithms, default yes')
    args = vars(parser.parse_args())

    matrix_file = None
    gen_file = None
    (nd_dataset, nd_templates, class_labels) = process_full_dataset()
    #(nd_dataset, iitd_dataset) = process_dataset()
    #TODO I believe this is a symmetric curve.  I tried with BN254 and it was much much slower.
    group_name = 'MNT159'
    vector_length = len(nd_dataset[0][0])

    if args['matrix_file'] and args['generator_file']:
        matrix_file = args['matrix_file'][0]
        gen_file = args['generator_file'][0]

    save = False
    database = None
    parallel = args['parallel']
    if args['save']:
        save = True
    if args['benchmark_key_gen']:
        database={}
        print("Benchmarking Multi Basis Generation", flush=True)
        print("Number Bases, Setup Time Av, Setup Time STDev, KeyGen Time Avg, KeyGen Time STDEv, Key size Avg, "
              "Key Size STDev")
        for i in range(65):
            database[i] = bench_keygen(n=vector_length, group_name=group_name,
                                    ipescheme=multibasispredipe.MultiBasesPredScheme, iterations=10,
                                    matrix_file=matrix_file, gen_file=gen_file, save_keys=save, num_bases=65 - i)

        print("Benchmarking Barbosa Key Generation", flush=True)
        database[65] = bench_keygen(n=vector_length, group_name=group_name,
                                ipescheme=predipe.BarbosaIPEScheme, iterations=10,
                                matrix_file=matrix_file, gen_file=gen_file, save_keys=save, num_bases=1)

    if args['load']:
        database = {}
        for i in range(65):
            database[i] = prox_search.ProximitySearch(vector_length, multibasispredipe.MultiBasesPredScheme)
            database[i].read_key_from_file(matrix_file + str(65 - i), gen_file + str(65 - i))
        database[65] = prox_search.ProximitySearch(vector_length, predipe.BarbosaIPEScheme, group_name)
        database[65].read_key_from_file(matrix_file, gen_file)

    if args['benchmark_enc']:
        if database is None:
            print("No initialization, exiting")
            exit(1)

        print("Benchmarking Multibasis Encryption", flush=True)
        print("Number Bases, Parallel, Time Avg, Time StDev, Size Avg, Size StDev")
        for i in range(65):
            bench_enc_data(n=vector_length, database=database[i], dataset=nd_templates, iterations=10,
                           parallel=parallel)

        print("Benchmarking Barbosa Encryption", flush=True)
        print("Number Bases, Parallel, Time Avg, Time StDev, Size Avg, Size StDev")
        bench_enc_data(n=vector_length, database=database[65], dataset=nd_templates, iterations=10, parallel=parallel)

    if args['benchmark_queries']:
        if database is None:
            print("No initialization, exiting")
            exit(1)
        print("Benchmarking Multi Basis Query Time", flush=True)
        print("Token time avg, Token time STDev, Search time Avg, Search time STDev, TAR, FAR")
        for i in range(66):
            if i == 65:
                print("Benchmarking Query Time")
                print("Token time avg, Token time STDev, Search time Avg, Search time STDev, TAR, FAR")
            database[i].encrypt_dataset_parallel(nd_templates)
            bench_queries(n=vector_length, database=database[i], queryset=nd_dataset, iterations=10, t=8, parallel=parallel)

    if args['benchmark_accuracy']:
        if database is None:
            print("No initialization, exiting")
            exit(1)
        print("Benchmarking Accuracy")
        print("TAR, FAR")
        bench_accuracy(n=vector_length, database=database[65], queryset=nd_dataset, iterations=1, t=8, parallel=parallel)
