

import sys, os, math
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))

from fhipe import multibasispredipe, prox_search



#Doing some basic testing
n=6
group_name='MNT159'
barbosa = multibasispredipe.MultiBasesPredScheme(n, group_name, 3)
barbosa.generate_keys()

print("Testing Basic Multi-basis Predicate Functionality")
x1 = [1, -1, -1, 1, -1, 1]
ctx = barbosa.encrypt(x1)
y1 = [1, 1, 1, 1, 1, 1]
tky1 = barbosa.keygen(y1)
tky2 = barbosa.keygen([1, 5, 1, 1, 1, 1])
x2 = [0, 0, 0, 0, 0, 0]
ctzero = barbosa.encrypt(x2)
assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky1, group_name))
assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctzero, tky1))
assert(not multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky2))
print("Test passed.")

# print("Testing Proximity Search")
# n=4
# group_name='MNT159'
# database = prox_search.ProximitySearch(n, predipe.BarbosaIPEScheme, group_name)
# data = [[0, 1, 0, 1], [1, 0, 1, 0]]
# database.encrypt_dataset(data)
#
#
# query = [0,1,0,0]
# encrypted_query = database.generate_query(query, 1)
# relevant_indices = database.search(encrypted_query)
# print("The matches are "+str(relevant_indices))
