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
import concurrent

"""
Implementation of Ahmad et al. Proximity Search Scheme 
"""

import sys, os, math, random, time, zlib, secrets, dill, threading, time, asyncio
from math import ceil
from charm.core.engine.util import objectToBytes,bytesToObject

# Path hack
sys.path.insert(0, os.path.abspath('charm'))
sys.path.insert(1, os.path.abspath('../charm'))

from subprocess import call, Popen, PIPE

from pathos.multiprocessing import ProcessingPool as Pool, cpu_count


class ProximitySearch():
    def __init__(self, n, predicate_scheme, group_name='MNT159', simulated=False):
        self.predicate_scheme = predicate_scheme
        self.predinstance = predicate_scheme(n + 1, group_name, simulated)
        self.public_parameters = None
        self.vector_length = n
        self.enc_data = None
        self.matrix_file = None
        self.generators_file = None

    def generate_keys(self):
        self.predinstance.generate_keys()
        self.public_parameters = self.predinstance.getPublicParameters()

    def serialize_key(self, matrix_filename, generator_filename):
        self.predinstance.serialize_key(matrix_filename, generator_filename)
        self.matrix_file = matrix_filename
        self.generators_file = generator_filename



    def deserialize_key(self, matrix_filename, generator_filename):
        self.predinstance.deserialize_key(matrix_filename, generator_filename)
        self.public_parameters = self.predinstance.getPublicParameters()
        self.matrix_file = matrix_filename
        self.generators_file = generator_filename

    @staticmethod
    def augment_encrypt(n, predicate_scheme, group_name, matrix_filename, generator_filename, pp, vec_list):
        predipe = predicate_scheme(n+1, group_name)
        predipe.deserialize_key(matrix_filename, generator_filename)
        predipe.public_parameters = pp

        c_list = []
        for vec in vec_list:
            x2 = []
            for x in vec:
                if x == 1:
                    x2.append(1)
                else:
                    x2.append(-1)
            x2.append(-1)
            c_list.append(predipe.encrypt(x2))

        # store encrypted data chunk in file ciphertexts_pid
        with open("ciphertexts_" + str(os.getpid()), "wb") as enc_file:
            enc_file.write(objectToBytes(c_list, predipe.group))
            enc_file.close()
    # TODO will need to augment this to store class identifier

    def encrypt_dataset_parallel(self, data_set):
        for data_item in data_set:
            if len(data_item) != self.vector_length:
                raise ValueError("Improper Vector Size")
        self.enc_data = {}
        i = 0

        processes = cpu_count()
        data_set_split = []
        data_set_len = len(data_set)
        #TODO check this actually produces the right indices
        for j in range(processes):
            data_set_split.append(data_set[ceil(j*data_set_len/processes):ceil((j+1)*data_set_len/processes)])
        # print(data_set_split)
        # result_list = []

        #TODO should not be hardcoded but cannot figure out how to get it from predicate scheme ...
        group_name = 'MNT159'

        # TODO This is not performing as well as I'd like, not sure why.  Same pattern as search
        with Pool(processes) as p:
            with concurrent.futures.ProcessPoolExecutor(processes) as executor:
                future_list = {executor.submit(self.augment_encrypt, self.vector_length, self.predicate_scheme, group_name,
                                               self.matrix_file, self.generators_file, self.public_parameters, data_set_component)
                               for data_set_component in data_set_split
                               }
                # for future in concurrent.futures.as_completed(future_list):
                    # res = future.result()
                    # if res is not None:
                    #     print(res)
                    #     #self.enc_data[i] = res


    def encrypt_dataset(self, data_set):
        for data_item in data_set:
            if len(data_item) != self.vector_length:
                raise ValueError("Improper Vector Size")
        self.enc_data = {}
        i = 0

        for x in data_set:
            x2 = [xi if xi == 1 else -1 for xi in x]
            x2.append(-1)
            self.enc_data[i] = self.predinstance.encrypt(x2)
            i = i + 1

    def generate_query(self, query, distance):
        encoded_query = [xi if xi == 1 else -1 for xi in query]
        query_set = []
        for i in range(distance + 1):
            temp_query = list(encoded_query)
            temp_query.append(self.vector_length - 2 * i)
            query_set.append(temp_query)

        # print("Query set is " + str(query_set))
        encrypted_query = []
        while (len(query_set) > 0):
            next_to_encode = secrets.randbelow(len(query_set))
            encrypted_query.append(self.predinstance.keygen(query_set[next_to_encode]))
            query_set.remove(query_set[next_to_encode])
        return encrypted_query


    async def search_parallel(self, query):

        async def match_item(decrypt_method, pub, index, ciphertext, token):
            print("Searching on item "+str(index))
            result_list=[]
            for subquery in token:
                if decrypt_method(pub, ciphertext, subquery):
                    result_list.append(index)
                    break
            return result_list

        result_list = []
        taskvec = []
        for x in range(len(self.enc_data)):
            taskvec.append(asyncio.create_task(match_item(self.predinstance.decrypt, self.public_parameters, x, self.enc_data[x], query)))

        combined_list = await asyncio.wait(taskvec)
        result_list = [item for sublist in combined_list for item in sublist]
        return result_list



    async def search_parallel_2(self, query):
        result_list_main = []

        async def search_worker(name, queue):
            # Get a "work item" out of the queue.
            (decrypt_method, pub, start_index, end_index, token) = await queue.get()
            result_list = []
            print(str(name) + " "+str(start_index)+ " "+str(end_index))
            await asyncio.sleep(.001)
            for current_index in range(start_index, end_index):
            #TODO this is not asynchronous but I don't know why
                print("Searching for index "+str(current_index))
                for subquery in token:
                    if decrypt_method(pub, self.enc_data[current_index], subquery):
                        result_list.append(current_index)
                        break

            print(str(name) + " " + str(result_list))
            if result_list is not None:
                result_list_main = result_list_main + result_list
            # Notify the queue that the "work item" has been processed.
            queue.task_done()

        # Create a queue that we will use to store our "workload".
        queue = asyncio.Queue()
        print(os.cpu_count())
        number_records = len(self.enc_data)
        chunk_size = ceil(number_records/os.cpu_count())

        for x in range(os.cpu_count()):
            start = chunk_size*x
            end = chunk_size*(x+1)
            if end>number_records:
                end = number_records
            if(start<end):
                queue.put_nowait((self.predinstance.decrypt, self.public_parameters, start, end,query))


        tasks = []
        for i in range(os.cpu_count()):
            task = asyncio.create_task(search_worker('worker'+str(i), queue))
            tasks.append(task)

        print("Number of workers is "+str(len(tasks)))

        await queue.join()

        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)
        print(result_list_main)



    def search(self, query):
        result_list = []

        for x in self.enc_data:
            index = None
            for subquery in query:
                if self.predinstance.decrypt(self.predinstance.getPublicParameters(), self.enc_data[x], subquery):
                    index = x
                    break
            if index is not None:
                result_list.append(index)
        return result_list

    @staticmethod
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

    def get_database_size(self):
        running_total = 0
        for x in self.enc_data:
            running_total += self.get_ct_size(self.enc_data[x])
        return running_total

    def get_seckey_size(self):
        matrix_file = "matrix.temp"
        gen_file = "gen.temp"
        self.predinstance.serialize_key(matrix_file, gen_file)
        running_total = os.path.getsize(matrix_file) + os.path.getsize(gen_file)
        os.remove(matrix_file)
        os.remove(gen_file)
        return running_total
