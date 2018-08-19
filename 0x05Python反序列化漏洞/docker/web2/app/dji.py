import string
import random

print(string.ascii_letters)

print(string.digits)

print(''.join(random.choice(string.ascii_letters + string.digits)
                         for x in range(4)))