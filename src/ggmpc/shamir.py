from functools import reduce

def split(curve, s, t, n=None, I=None):
  """
  Perform Shamir sharing on the secret `s` to the degree `t - 1` split `n`
  ways. The split secret requires `t` shares to be reconstructed.

  :param s: Secret to split.
  :type s: int
  :param t: Share threshold required to reconstruct secret.
  :type t: int
  :param n: Total number of shares to split secret into.
  :type n: int, optional
  :param I: Indices used for each party. Defaults to range(1, 1 + n).
  :type I: list, optional
  :return: Dictionary of shares. Each key is an int in the range 1<=x<=n
    representing that share's free term.
  :rtype dict:
  """
  if I == None:
    assert n != None
    I = range(1, 1 + n)
  elif n == None:
    n = len(I)
  assert t > 1
  assert t <= n
  coefs = [curve.scalar_random() for i in range(0, t - 1)] + [s]
  shares = dict()
  for x in I:
    shares[x] = reduce(
      lambda partial, coef: \
      curve.scalar_add(coef, curve.scalar_mul(partial, x)),
      coefs,
    )
  return shares

def combine(curve, shares):
  """
  Reconstitute a secret from a dictionary of shares. The number of shares must
  be equal to `t` to reconstitute the original secret.

  :param shares: Dictionary of shares. Each key is the free term of the share.
  :type shares: dict
  :return: Reconstituted secret.
  :rtype: int
  """
  s = 0
  for xi in shares:
    yi = shares[xi]
    num = 1
    for xj in shares:
      if xi != xj:
        num = curve.scalar_mul(num, xj)
    denum = 1
    for xj in shares:
      if xi != xj:
        denum = curve.scalar_mul(denum, curve.scalar_sub(xj, xi))
    s = curve.scalar_add(
      curve.scalar_mul(curve.scalar_mul(num, curve.scalar_invert(denum)), yi),
      s,
    )
  return s
