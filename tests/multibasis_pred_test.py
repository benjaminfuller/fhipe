

import sys, os, math
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))

from fhipe import multibasispredipe, prox_search



# Doing some basic testing
print("Testing Basic Multi-basis Predicate Functionality (n = 8)")
n = 8
group_name = 'MNT159'

x1 = [1, -1, 1, -1, 1, -1, 1, -1]
y1 = [1, 1, 1, 1, 1, 1, 1, 1]
y2 = [1, 5, 1, 1, 1, 1, 1, 1]
x2 = [0, 0, 0, 0, 0, 0, 0, 0]

print("Testing for sigma = 1")
barbosa = multibasispredipe.MultiBasesPredScheme(n, group_name, 1)
barbosa.generate_keys()

ctx = barbosa.encrypt(x1)
tky1 = barbosa.keygen(y1)
tky2 = barbosa.keygen(y2)
ctzero = barbosa.encrypt(x2)

assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky1, group_name))
assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctzero, tky1))
assert(not multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky2))
print("Test passed.")


print("Testing for sigma = 4")
barbosa = multibasispredipe.MultiBasesPredScheme(n, group_name, 4)
barbosa.generate_keys()

ctx = barbosa.encrypt(x1)
tky1 = barbosa.keygen(y1)
tky2 = barbosa.keygen(y2)
ctzero = barbosa.encrypt(x2)

assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky1, group_name))
assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctzero, tky1))
assert(not multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky2))
print("Test passed.")


print("Testing for sigma = 3")
barbosa = multibasispredipe.MultiBasesPredScheme(n, group_name, 3)
barbosa.generate_keys()

ctx = barbosa.encrypt(x1)
tky1 = barbosa.keygen(y1)
tky2 = barbosa.keygen(y2)
ctzero = barbosa.encrypt(x2)

assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky1, group_name))
assert(multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctzero, tky1))
assert(not multibasispredipe.MultiBasesPredScheme.decrypt(barbosa.getPublicParameters(), ctx, tky2))
print("Test passed.")

