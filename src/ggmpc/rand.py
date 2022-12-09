from Crypto.Random.random import getrandbits
from Crypto.Util.number import getRandomRange
from math import gcd

def get_random_coprime_to(x):
  while True:
    y = getrandbits(x.bit_length())
    if y > 0 and gcd(x, y) == 1:
      return y

def get_random_less_than(x):
  return getRandomRange(1, x)
