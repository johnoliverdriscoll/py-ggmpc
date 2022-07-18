""" EdDSA threshold signing library. """

from functools import reduce
from . import shamir
from .rand import get_random_less_than

class Eddsa:
  """
  Threshold signing over the EdDSA cryptosystem.

  :param curve: The EdDSA curve to use.

  :type curve: ggmpc.Curve
  """

  def __init__(self, curve):
    self.curve = curve

  def secret_generate(self):
    """
    Generate a secret that can be used as a contribution in DKG.

    :return: A secret.

    :rtype: dict
    """
    sk = get_random_less_than(2 ** 256)
    sk = sk.to_bytes((sk.bit_length() + 7) // 8, 'little')
    h = self.curve.hash(sk).digest()
    h = b'\x00' * (64 - len(h)) + h
    u = [x for x in h[0:32]]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = self.curve.scalar_reduce(int.from_bytes(bytes(u + [0] * 32), 'little'))
    prefix = [x for x in h[32:]]
    prefix = [0] * 32 + prefix
    prefix = self.curve.scalar_reduce(int.from_bytes(bytes(prefix), 'little'))
    return {
      'u': u,
      'prefix': prefix,
    }

  def key_share(self, i, t, n, sk=None):
    """
    Generate shares for player at index `i` of key split `(t,n)` ways.

    :param i: Player index.

    :type i: int

    :param t: Signing threshold.

    :Type t: int

    :param n: Number of shares.

    :type n: int

    :return: Dictionary of shares. Share at index `i` is a private u-share.
      Other indices are y-shares to be distributed to players at their
      corresponding index.

    :rtype: dict
    """
    assert i > 0 and i <= n
    if sk == None:
      sk = self.secret_generate()
    u = shamir.split(self.curve, sk['u'], t, n)
    v = u['v']
    y = v[0]
    P_i = {
      'i': i,
      'y': y,
      'u': u[i],
      'prefix': sk['prefix'],
    }
    shares = {
      P_i['i']: P_i,
    }
    for i in u:
      if i != 'v' and i != P_i['i']:
        shares[i] = {
          'i': i,
          'j': P_i['i'],
          't': t,
          'y': y,
          'v': v[1:],
          'u': u[i],
        }
    return shares

  def key_combine(self, P):
    """ 
    Combine data shared during the key generation protocol.

    :param P: Tuple of shares for every player. Must include player's private
      p-share and n-shares received from all other players.

    :type P: tuple

    :return: Dictionary of shares. Share at player's index is a private p-share.
      Other indices are j-shares to be used when generating signing shares.

    :rtype: dict
    """
    P_i = next(filter(lambda P_i: not 'j' in P_i, P))
    # Verify the shares.
    for P_j in filter(lambda P_j: 'j' in P_j, P):
      v, t = P_j['y'], 1
      for vsj in P_j['v']:
        t = self.curve.scalar_mul(t, P_j['i'])
        vjt = self.curve.point_mul(vsj, t)
        v = self.curve.point_add(v, vjt)
      sigmaG_i = self.curve.scalar_mul_base(P_j['u'])
      if sigmaG_i != v:
        raise RuntimeError('could not verify share from participant ' + str(P_j['j']))
    # Compute the public key.
    y = reduce(
      self.curve.point_add,
      map(lambda P_i: P_i['y'], P),
    )
    # Add secret shares of $x$.
    x = reduce(self.curve.scalar_add, map(lambda P_i: P_i['u'], P))
    P_i = {
      'i': P_i['i'],
      'y': y,
      'x': x,
      'prefix': P_i['prefix'],
    }
    players = {
      P_i['i']: P_i,
    }
    for P_j in P:
      if 'j' in P_j:
        players[P_j['j']] = {
          'i': P_i['i'],
          'j': P_j['j'],
        }
    return players

  def sign_share(self, M, S):
    """
    Create signing shares.

    :param M: Message to sign.

    :type M: bytes

    :param S: Tuple of shares for each signer. Must include player's private
      p-share and j-shares received from all other signers.

    :type S: tuple

    :return: Dictionary of shares. Share at signer's index is a private x-share.
      Other indices are r-shares to be distributed to signers at their
      corresponding index.

    :rtype: dict
    """
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    I = list(map(lambda S_i: S_i['i'] if not 'j' in S_i else S_i['j'], S))
    digest = self.curve.hash(
      S_i['prefix'].to_bytes(32, 'big') \
      + M \
      + self.curve.scalar_random().to_bytes(32, 'big')
    ).digest()
    r = self.curve.scalar_reduce(int.from_bytes(digest, 'big'))
    R = self.curve.scalar_mul_base(r)
    r = shamir.split(self.curve, r, len(S), I=I)
    shares = {
      S_i['i']: {
        'i': S_i['i'],
        'y': S_i['y'],
        'x': S_i['x'],
        'r': r[S_i['i']],
        'R': R,
      },
    }
    for S_j in S:
      if 'j' in S_j:
        shares[S_j['j']] = {
          'i': S_j['j'],
          'j': S_i['i'],
          'r': r[S_j['j']],
          'R': R,
        }
    return shares

  def sign(self, M, S):
    """
    Sign a message.

    :param M: Message to sign.

    :type M: bytes

    :param S: Tuple of shares for each signer. Must include signer's private
      x-share and r-shares received from other signers.

    :type S: tuple

    :return: Signature share to be combined with all other signers' signature
      shares.

    :rtype: dict
    """
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    R = reduce(self.curve.point_add, map(lambda S_i: S_i['R'], S))
    digest = self.curve.hash(
      R.to_bytes(32, 'little') \
      + S_i['y'].to_bytes(32, 'little') \
      + M
    ).digest()
    k = self.curve.scalar_reduce(int.from_bytes(digest, 'little'))
    r = reduce(self.curve.scalar_add, map(lambda S_i: S_i['r'], S))
    gamma = self.curve.scalar_add(r, self.curve.scalar_mul(k, S_i['x']))
    return {
      'i': S_i['i'],
      'y': S_i['y'],
      'gamma': gamma,
      'R': R,
    }

  def sign_combine(self, S):
    """
    Combine signature shares to produce the final signature.

    :param S: Tuple of gamma-shares for each signer.

    :type S: tuple

    :return: Fully reconstructed signature.

    :rtype: dict
    """
    y = next(iter(S))['y']
    R = next(iter(S))['R']
    shares = {}
    for S_i in S:
      shares[S_i['i']] = S_i['gamma']
    sigma = shamir.combine(self.curve, shares)
    return {
      'y': y,
      'R': R,
      'sigma': sigma,
    }

  def verify(self, M, sig):
    """
    Verify a signature.

    :param M: Signed message.

    :type M: bytes

    :param sig: Signature.

    :type sig: dict

    :return: True if signature is valid; False otherwise.

    :rtype: bool
    """
    return self.curve.verify(
      sig['y'].to_bytes(32, 'little'),
      M,
      sig['R'].to_bytes(32, 'little') + sig['sigma'].to_bytes(32, 'little'),
    )
