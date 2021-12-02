""" MPC threshold signature library. """

import phe, random
from functools import reduce
from . import shamir

class Ecdsa:
  """
  Threshold signing over the ECDSA cryptosystem.

  :param curve: The ECDSA curve to use.

  :type curve: ggmpc.Curve
  """

  def __init__(self, curve):
    self.curve = curve

  def key_share(self, i, t, n):
    """
    Generate shares for player at index `i` of key split `(t,n)` ways.

    :param i: Player index.

    :type i: int

    :param t: Signing threshold.

    :type t: int

    :param n: Number of shares.

    :type n: int

    :return: Dictionary of shares. Share at index `i` is a private p-share.
      Other indices are n-shares to be distributed to players at their
      corresponding index.

    :rtype: dict
    """
    assert i > 0 and i <= n
    # Generate additively homomorphic encryption key.
    pk, sk = phe.generate_paillier_keypair(n_length=3072)
    # Generate $u_i \in_R \Z_q$.
    u = self.curve.scalar_random()
    y = self.curve.point_mul_base(u)
    # Compute secret shares of their $u_i$.
    u = shamir.split(self.curve, u, t, n)
    P_i = {
      'i': i,
      'p': sk.p,
      'q': sk.q,
      'y': y,
      'u': u[i],
    }
    shares = {
      P_i['i']: P_i,
    }
    for i in u:
      if i != P_i['i']:
        shares[i] = {
          'i': i,
          'j': P_i['i'],
          'n': pk.n,
          'y': y,
          'u': u[i],
        }
    return shares

  def key_combine(self, P):
    """
    Combine data shared during the key generation protocol.

    :param P: Tuple of shares for every player. Must include player's private
      p-share and n-shares received from all other players.

    :type P: tuple

    :return: Dictionary of shares. Share at player's index is a private x-share.
      Other indices are y-shares to be used when generating signing shares.

    :rtype: dict
    """
    P_i = next(filter(lambda P_i: not 'j' in P_i, P))
    # Compute the public key.
    y = reduce(
      self.curve.point_add,
      map(lambda P_i: P_i['y'], P),
    )
    # Add secret shares of $x$.
    x = reduce(self.curve.scalar_add, map(lambda P_i: P_i['u'], P))
    players = {
      P_i['i']: {
        'i': P_i['i'],
        'p': P_i['p'],
        'q': P_i['q'],
        'y': y,
        'x': x,
      }
    }
    for P_j in P:
      if 'j' in P_j:
        players[P_j['j']] = {
          'i': P_i['i'],
          'j': P_j['j'],
          'n': P_j['n'],
        }
    return players

  def sign_share(self, S):
    """
    Create signing shares.

    :param S: Tuple of shares for each signer. Must include player's private
      x-share and y-shares received from all other signers.

    :type S: tuple

    :return: Dictionary of shares. Share at signer's index is a private w-share.
      Other indices are k-shares to be distributed to signers at their
      corresponding index.

    :rtype: dict
    """
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    pk = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
    # Select $k_i, \gamma_i \in_R Z_q$.
    k = self.curve.scalar_random()
    gamma = self.curve.scalar_random()
    # Map $x_i$ in $(n,t)$ to $w_i$ in $(t,t)$.
    d = reduce(
      lambda acc, S_j: self.curve.scalar_mul(
        self.curve.scalar_sub(S_j['j'], S_i['i']),
        acc,
      ),
      [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
    )
    w = reduce(
      self.curve.scalar_mul,
      [S_i['x'], self.curve.scalar_invert(d)],
      reduce(
        lambda acc, S_j: self.curve.scalar_mul(S_j['j'], acc),
        [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
      ),
    )
    signers = {
      S_i['i']: {
        'i': S_i['i'],
        'p': S_i['p'],
        'q': S_i['q'],
        'y': S_i['y'],
        'k': k,
        'w': w,
        'gamma': gamma,
      },
    }
    for S_j in S:
      if 'j' in S_j:
        signers[S_j['j']] = {
          'i': S_j['j'],
          'j': S_i['i'],
          'n': pk.n,
          'k': pk.encrypt(k).ciphertext(),
        }
    return signers

  def sign_convert(self, S):
    """
    Perform multiplicitive-to-additive (MtA) share conversion with another
    signer.

    :param S: Tuple of shares for this signing pair. Must include either:

      * The signer's private w-share and the k-share received from the other
        signer.

      * The signer's private x-share, the signer's y-share for the other signer,
        and the k-share received from the other signer. Use only in a 2-of-\*
        threshold setup.

      * The signer's private beta-share and the alpha-share received from the
        other signer.

      * The signer's private beta-share and the mu-share received from the other
        player.

    :type S: tuple

    :return: Dictionary of shares. Share at signer's index is either:

      * A private beta-share if `S` included a k-share.

      * A private private gamma-share if `S` included an alpha-share or a
        mu-share.

      If there is another index, it will be a share to send to the other signer.
      The share will be either:

      * An alpha-share if `S` included a k-share.

      * A mu-share if `S` included an alpha-share.

      Note that if `S` included a mu-share, there is no share to send to the
      other player and this function returns a dictionary containing a single
      index which will point to the signer's private gamma-share.

    :rtype: dict
    """
    S_i, S_j = None, None
    if len(S) > 2:
      S_j = next(filter(lambda S_j: 'k' in S_j, S))
      S = self.sign_share(list(filter(lambda S_i: not 'k' in S_i, S)))
      S_i = S[next(filter(lambda i: not 'j' in S[i], S))]
    elif len(S) == 2:
      S_i = next(filter(lambda S_i: not 'j' in S_i, S))
      S_j = next(filter(lambda S_j: 'j' in S_j, S))
    else:
      raise RuntimeError('expected at least 2 arguments')
    assert S_i['i'] == S_j['i']
    S_i = S_i.copy()
    S_j = S_j.copy()
    if 'alpha' in S_j:
      pk = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
      sk = phe.PaillierPrivateKey(pk, S_i['p'], S_i['q'])
      alpha = sk.decrypt(phe.EncryptedNumber(pk, S_j['alpha']))
      S_i['alpha'] = self.curve.scalar_reduce(alpha)
      mu = sk.decrypt(phe.EncryptedNumber(pk, S_j['mu']))
      S_i['mu'] = self.curve.scalar_reduce(mu)
      del S_i['p']
      del S_i['q']
      del S_j['alpha']
      del S_j['mu']
    if 'k' in S_j:
      pk = phe.PaillierPublicKey(S_j['n'])
      k = phe.EncryptedNumber(pk, S_j['k'])
      # MtA $k_j, \gamma_i$.
      beta0 = random.SystemRandom().randint(1, pk.max_int)
      S_i['beta'] = self.curve.scalar_negate(beta0)
      alpha = S_i['gamma'] * k + pk.encrypt(beta0)
      S_j['alpha'] = alpha.ciphertext()
      # MtA $k_j, w_i$.
      nu0 = random.SystemRandom().randint(1, pk.max_int)
      S_i['nu'] = self.curve.scalar_negate(nu0)
      mu = S_i['w'] * k + pk.encrypt(nu0)
      S_j['mu'] = mu.ciphertext()
      if 'alpha' in S_i:
        del S_j['n']
        del S_j['k']
      else:
        pk = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
        S_j['n'] = pk.n
        S_j['k'] = pk.encrypt(S_i['k']).ciphertext()
    if not 'alpha' in S_j and not 'k' in S_j:
      S_j = {
        'i': S_j['i'],
        'j': S_j['j'],
      }
    S_j['i'], S_j['j'] = S_j['j'], S_j['i']
    return {
      S_i['i']: S_i,
      S_j['i']: S_j,
    }

  def sign_combine(self, shares):
    """
    Combine gamma-shares for each of your signing pairs in the list of
    signers, or, combine s-shares to produce the final signature.

    :param shares: Tuple of gamma-shares or tuple of s-shares.

    :type shares: tuple

    :return: If `shares` included gamma-shares, returns a dictionary of
      shares. Share at signer's index is a private omicron-share. Other indices
      are delta-shares to distribute to all other signers. If `shares` included
      s-shares, returns a fully reconstructed signature.

    :rtype: dict
    """
    assert len(shares) > 0
    # Check if combining $s$ shares.
    if 'r' in shares[0] and 's' in shares[0]:
      assert len(shares) > 1
      # Every r must match.
      r = shares[0]['r']
      assert reduce(
        lambda a, b: a and b,
        map(lambda share: share['r'] == r, shares[1:])
      )
      s = reduce(
        self.curve.scalar_add,
        map(lambda share: share['s'], shares),
      )
      # Normalize s.
      s = self.curve.order() - s if s > self.curve.order() // 2 else s
      return {
        'y': shares[0]['y'],
        'r': r,
        's': s,
      }
    # Combine the pairs into a map of signers.
    P_i = []
    S = {}
    for pair in shares:
      if type(pair) == dict:
        for i in pair:
          if not 'j' in pair[i]:
            P_i.append(pair[i])
          else:
            S[i] = pair[i].copy()
      else:
        for share in pair:
          if not 'j' in share:
            P_i.append(share)
          else:
            S[share['i']] = share.copy()
    alpha = map(lambda P_i: P_i['alpha'], P_i)
    beta = map(lambda P_i: P_i['beta'], P_i)
    mu = map(lambda P_i: P_i['mu'], P_i)
    nu = map(lambda P_i: P_i['nu'], P_i)
    # Compute $\delta_i = k_i \gamma_i + \sum_{j \ne i} \alpha_{ij}
    #                                  + \sum_{j \ne i} \beta_{ji}$.
    delta = self.curve.scalar_add(
      self.curve.scalar_mul(P_i[0]['k'], P_i[0]['gamma']),
      self.curve.scalar_add(
        reduce(self.curve.scalar_add, alpha),
        reduce(self.curve.scalar_add, beta),
      ),
    )
    # Compute $\omicron_i = k_i \w_i + \sum_{j \ne i} \mu_{ij}
    #                                + \sum_{j \ne i} \nu_{ji}$.
    omicron = self.curve.scalar_add(
      self.curve.scalar_mul(P_i[0]['k'], P_i[0]['w']),
      self.curve.scalar_add(
        reduce(self.curve.scalar_add, mu),
        reduce(self.curve.scalar_add, nu),
      ),
    )
    Gamma = self.curve.point_mul_base(P_i[0]['gamma'])
    return reduce(
      lambda shares, i: {**shares, **{
        i: {
          'i': i,
          'j': P_i[0]['i'],
          'delta': delta,
          'Gamma': Gamma,
        },
      }},
      S,
      {
        P_i[0]['i']: {
          'i': P_i[0]['i'],
          'y': P_i[0]['y'],
          'k': P_i[0]['k'],
          'omicron': omicron,
          'delta': delta,
          'Gamma': Gamma,
        },
      }
    )

  def sign(self, M, S):
    """
    Sign a message.

    :param M: Message to sign.

    :type M: bytes

    :param S: Tuple of shares for each signer. Must include signer's private
       omicron-share and delta-shares received from other signers.

    :type shares: tuple

    :return: Signature share to be combined with all other signers' signature
      shares.

    :rtype: dict
    """
    m = int.from_bytes(self.curve.hash(M).digest(), 'big')
    S_i = next(filter(lambda share: 'k' in share, S))
    delta = reduce(
      self.curve.scalar_add,
      map(lambda S_j: S_j['delta'], S),
    )
    # Compute $R = [\Si_{i \in S} \Gamma_i]^\delta^{-1}$ and $r = H'(R)$.
    R = self.curve.point_mul(
      reduce(
        self.curve.point_add,
        map(lambda S_j: S_j['Gamma'], S),
      ),
      self.curve.scalar_invert(delta),
    )
    r = int(R.x())
    # Compute $s_i = m k_i + r \omicron_i$.
    s = self.curve.scalar_add(
      self.curve.scalar_mul(m, S_i['k']),
      self.curve.scalar_mul(r, S_i['omicron']),
    )
    return {
      'i': S_i['i'],
      'y': S_i['y'],
      'r': r,
      's': s,
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
      sig['y'],
      M,
      sig['r'].to_bytes(32, 'big') + sig['s'].to_bytes(32, 'big'),
    )

class Eddsa:
  """
  Threshold signing over the EdDSA cryptosystem.

  :param curve: The EdDSA curve to use.

  :type curve: ggmpc.Curve
  """

  def __init__(self, curve):
    self.curve = curve

  def key_share(self, i, t, n):
    """
    Generate shares for player at index `i` of key split `(t,n)` ways.

    :param i: Player index.

    :type i: int

    :param t: Signing threshold.

    :type t: int

    :param n: Number of shares.

    :type n: int

    :return: Dictionary of shares. Share at index `i` is a private u-share.
      Other indices are y-shares to be distributed to players at their
      corresponding index.

    :rtype: dict
    """
    assert i > 0 and i <= n
    sk = random.SystemRandom().randrange(2 ** 256)
    sk = sk.to_bytes((sk.bit_length() + 7) // 8, 'little')
    h = self.curve.hash(sk).digest()
    h = b'\x00' * (64 - len(h)) + h
    u = [x for x in h[0:32]]
    u[0] &= 248
    u[31] &= 63
    u[31] |= 64
    u = self.curve.scalar_reduce(int.from_bytes(bytes(u + [0] * 32), 'little'))
    y = self.curve.point_mul_base(u)
    u = shamir.split(self.curve, u, t, n)
    prefix = [x for x in h[32:]]
    prefix = [0] * 32 + prefix
    prefix = self.curve.scalar_reduce(int.from_bytes(bytes(prefix), 'little'))
    P_i = {
      'i': i,
      'y': y,
      'u': u[i],
      'prefix': prefix,
    }
    shares = {
      P_i['i']: P_i,
    }
    for i in u:
      if i != P_i['i']:
        shares[i] = {
          'i': i,
          'j': P_i['i'],
          'y': y,
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
          'i': P_j['j'],
          'j': P_i['i'],
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
    I = list(map(lambda S_i: S_i['i'], S))
    digest = self.curve.hash(
      S_i['prefix'].to_bytes(32, 'big') \
      + M \
      + self.curve.scalar_random().to_bytes(32, 'big')
    ).digest()
    r = self.curve.scalar_reduce(int.from_bytes(digest, 'big'))
    R = self.curve.point_mul_base(r)
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
        shares[S_j['i']] = {
          'i': S_j['i'],
          'j': S_i['i'],
          'r': r[S_j['i']],
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
