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
Implementation of Ahmad et al. Proximity Search Scheme 
"""

import sys, os, math, random, time, zlib, secrets, dill, threading,time, concurrent.futures

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from subprocess import call, Popen, PIPE

from pathos.multiprocessing import ProcessingPool as Pool, cpu_count


def match_item(decrypt_method, pub, index, ciphertext, token):
    for subquery in token:
        if decrypt_method(pub, ciphertext, subquery):
            return index
            break
    return


class ProximitySearch():
    def __init__(self, n, predicate_scheme, group_name='MNT159', simulated=False):
        self.predinstance = predicate_scheme(n + 1, group_name, simulated)

        self.vector_length = n

    def generate_keys(self):
        self.predinstance.generate_keys()
        self.public_parameters = self.predinstance.getPublicParameters()

    def serialize_key(self, matrix_filename, generator_filename):
        self.predinstance.serialize_key(matrix_filename, generator_filename)

    def deserialize_key(self, matrix_filename, generator_filename):
        self.predinstance.deserialize_key(matrix_filename, generator_filename)
        self.public_parameters = self.predinstance.getPublicParameters()


    def encrypt_dataset(self, data_set):
        for data_item in data_set:
            if (len(data_item) != self.vector_length):
                raise ValueError("Improper Vector Size")

        self.enc_data = {}
        i = 0
        #print(data_set)
        for x in data_set:
            #print("Value to encrypt is " + str(x))
            x2 = [xi if xi == 1 else -1 for xi in x]
            x2.append(-1)
            #print("Data to encrypt is " + str(x2))
            self.enc_data[i] = self.predinstance.encrypt(x2)
            i = i + 1

    def generate_query(self, query, distance):
        encoded_query = [xi if xi == 1 else -1 for xi in query]
        query_set = []
        for i in range(distance + 1):
            temp_query = list(encoded_query)
            temp_query.append(self.vector_length - 2 * i)
            query_set.append(temp_query)

        #print("Query set is " + str(query_set))
        encrypted_query = []
        while (len(query_set) > 0):
            next_to_encode = secrets.randbelow(len(query_set))
            encrypted_query.append(self.predinstance.keygen(query_set[next_to_encode]))
            query_set.remove(query_set[next_to_encode])

        return encrypted_query

    def search(self, query):
        result_list = []
        with Pool(processes=cpu_count()) as p:
            data_val_aug = [(self.predinstance.decrypt, self.public_parameters, x, self.enc_data[x], query) for x in
                            self.enc_data]
            with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
                future_list = {executor.submit(match_item, self.predinstance.decrypt,
                                               self.public_parameters, x, self.enc_data[x], query)
                               for x in self.enc_data
                               }
                for future in concurrent.futures.as_completed(future_list):
                    res = future.result()
                    if res is not None:
                        result_list.append(res)
        return result_list

