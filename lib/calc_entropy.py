#!/usr/bin/env python3

import math
import sys

filename = sys.argv[1]

def entropy(verbose=0):
    with open(filename, "rb") as file:
        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros
    
        for byte in file.read():  # read in chunks for large files
    
            counters[byte] += 1  # increase counter for specified byte
    
        filesize = file.tell()  # we can get file size by reading current position
    
        probabilities = [counter / filesize for counter in counters.values()]  # calculate probabilities for each byte
    
        entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)  # final sum
    
        if verbose > 0 :
            print(filename.rsplit(".")[-2],entropy)
        else:
            print(entropy)


if __name__ == "__main__":
    entropy()
