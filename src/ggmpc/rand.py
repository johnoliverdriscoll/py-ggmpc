from Crypto.Util import number
from math import gcd

def get_random_coprime_to(x):
  while True:
    y = number.getStrongPrime(x.bit_length())
    if y > 0 and gcd(x, y) == 1:
      return y

def get_random_less_than(x):
  return number.getRandomRange(1, x)
