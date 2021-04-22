

import sys, os, math, argparse
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))

from fhipe import predipe, prox_search

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Benchmarking of Proximity Search Schemes.')
    parser.add_argument('--matrix_file', '-mf', nargs='*', help='The file for the matrices')
    parser.add_argument('--generator_file', '-gf', nargs='*', help='The file for the group generators')
    parser.add_argument('--save', '-s', const=1, type=int, nargs='?', default=0,
                        help='Write a secret key to file and quit')
    parser.add_argument('--load', '-l', const=1, type=int, nargs='?', default=0,
                        help='Load secret key from a file')
    parser.add_argument('--benchmark', '-b', const=1, type=int, nargs='?',
                        default=0, help='Perform Full benchmarking')
    parser.add_argument('--vector_length', '-v', const=1, type=int, nargs='?', default=64,
                        help='Specify the length of vectors for testing')
    args = vars(parser.parse_args())

    vector_length = args['vector_length']

    if(args['save'] and args['matrix_file'] and args['generator_file']):
        # Doing some basic testing
        group_name = 'MNT159'
        barbosa = predipe.BarbosaIPEScheme(n = vector_length)
        barbosa.generate_keys()
        secret_key = barbosa.serialize_key(args['matrix_file'][0], args['generator_file'][0])
        
    elif(args['load'] and args['matrix_file'] and args['generator_file']):
        group_name = 'MNT159'
        barbosa = predipe.BarbosaIPEScheme(n=vector_length, group_name=group_name)
        barbosa.deserialize_key(args['matrix_file'][0], args['generator_file'][0])
    else:
        group_name = 'MNT159'
        barbosa = predipe.BarbosaIPEScheme(n=vector_length)
        barbosa.generate_keys()

    print("Testing Basic Predicate Functionality")
    x1=[1, -1, -1, 1]
    ctx = barbosa.encrypt(x1)
    y1=[1, 1, 1, 1]
    y2=[1, 5, 1, 1]
    tky1 = barbosa.keygen(y1)
    tky2 = barbosa.keygen(y2)
    x2=[0, 0, 0, 0]
    ctzero = barbosa.encrypt(x2)
    assert(predipe.BarbosaIPEScheme.decrypt(barbosa.getPublicParameters(), ctzero, tky1))
    assert(not predipe.BarbosaIPEScheme.decrypt(barbosa.getPublicParameters(), ctx, tky2))
    assert(predipe.BarbosaIPEScheme.decrypt(barbosa.getPublicParameters(), ctx, tky1, group_name))


    exit(0)


    print("Testing Proximity Search")
    n=4
    group_name='MNT159'
    database = prox_search.ProximitySearch(n, predipe.BarbosaIPEScheme, group_name)
    data = [[0, 1, 0, 1], [1, 0, 1, 0]]
    database.encrypt_dataset(data)


    query = [0,1,0,0]
    encrypted_query = database.generate_query(query, 1)
    relevant_indices = database.search(encrypted_query)
    print("The matches are "+str(relevant_indices))
