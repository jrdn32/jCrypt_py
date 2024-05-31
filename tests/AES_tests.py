import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 

from jCrypt import *


state = np.array([0x115599DD,
                  0x2266AAEE,
                  0x3377BBFF,
                  0x4488CC11])


# Test AES shift_rows function
test = AES.shift_rows(state)

for i in range(len(test)):
    print(hex(test[i]))
print()



state = np.array([0xD4BF5D30,
                  0xD4BF5D30,
                  0xD4BF5D30,
                  0xD4BF5D30])

# Test AES mix_columns function
test = AES.mix_columns(state)

for i in range(len(test)):
    print(hex(test[i]))
print()


# Test AES encryption function
plaintext = "Two One Nine Two"
key = "Thats my Kung Fu"

test = AES.encrypt(plaintext, key)
print(test)
