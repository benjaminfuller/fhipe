import glob
import os
import numpy as np


def read_fvector(filePath):
    with open(filePath) as f:
        for line in f.readlines():
            return np.fromstring(line,sep = ",")


cwd = os.getcwd()
feat_list = glob.glob(cwd + "\\ND_proximity_irisR_features\\*")
f_1 = read_fvector(feat_list[0])

print("Notre Dame 0405:")
print ("Number of features: " + str(len(feat_list)))

print ("Vector dimensions: " + str(len(f_1)))

print ("Example feature vector: " + str(f_1))




cwd = os.getcwd()
feat_list = glob.glob(cwd + "\\IITD_proximity_irisR_features\\*")
f_1 = read_fvector(feat_list[0])
print("IITD:")

print ("Number of features: " + str(len(feat_list)))

print ("Vector dimensions: " + str(len(f_1)))

print ("Example feature vector: " + str(f_1))
