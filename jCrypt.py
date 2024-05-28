import numpy as np
import algs.AES as AES


class jCrypt:
    def __init__(self, sym_key, algorithm = "AES"):
        if (algorithm.upper() != "AES"):
            raise Exception("The specified algorithm is not supported yet")
        # Only AES-128, AES-196, and AES-256 are allowed
        if (sym_key.len() != 32 and sym_key.len() != 48 and sym_key.len() != 64):
            raise Exception("The length of the given key is not supported")

        self.algorithm = algorithm
        self.sym_key   = sym_key
