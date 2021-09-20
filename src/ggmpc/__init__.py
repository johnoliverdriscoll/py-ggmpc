import ecdsa, hashlib, phe, random
from functools import reduce

def key_share(i, t, n):
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
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  u = random.SystemRandom().randrange(1, q)
  y = ecdsa.ecdsa.generator_secp256k1 * u
  # Compute secret shares of their $u_i$.
  u = split(u, t, n)
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
  for i in range(1, 1 + n):
    if i != P_i['i']:
      shares[i] = {
        'i': i,
        'j': P_i['i'],
        'n': pk.n,
        'y': y,
        'u': u[i],
      }
  return shares

def key_combine(P):
  """ 
  Combine data shared during the key generation protocol.

  :param P: Tuple of shares for every player. Must include player's private
    p-share and n-shares received from all other players.

  :type P: tuple

  :return: Dictionary of shares. Share at player's index is a private x-share.
    Other indices are y-shares to be used when generating signing shares.

  :rtype: dict
  """
  P_i = next(filter(lambda P_i: 'p' in P_i, P))
  # Compute the public key.
  y = reduce(
    lambda y_i, y_j: y_i + y_j,
    map(lambda P_i: P_i['y'], P),
    ecdsa.ellipticcurve.INFINITY,
  )
  # Add secret shares of $x$.
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  x = sum(map(lambda P_i: P_i['u'], P)) % q
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

def sign_share(S):
  """
  Create signing shares.

  :param S: Tuple of shares for each signer. Must include player's private
    x-share and y-share received from all other signers.

  :type P: tuple

  :return: Dictionary of shares. Share at signer's index is a private w-share.
    Other indicies are k-shares to be distributed to signers at their
    corresponding index.

  :rtype: dict
  """
  S_i = next(filter(lambda S_i: 'p' in S_i, S))
  pk = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
  # Select $k_i, \gamma_i \in_R Z_q$.
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  k = random.SystemRandom().randrange(1, q)
  gamma = random.SystemRandom().randrange(1, q)
  # Map $x_i$ in $(n,t)$ to $w_i$ in $(t,t)$.
  d = reduce(
    lambda acc, S_j: acc * (S_j['j'] - S_i['i']) % q,
    [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
  )
  n = reduce(
    lambda acc, S_j: acc * S_j['j'],
    [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
  )
  w = int((S_i['x'] * pow(d, -1, q) * n) % q)
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
      
def sign_convert(S):
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
    S = sign_share(list(filter(lambda S_i: not 'k' in S_i, S)))
    S_i = S[next(filter(lambda i: not 'j' in S[i], S))]
  elif len(S) == 2:
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    S_j = next(filter(lambda S_j: 'j' in S_j, S))
  else:
    raise RuntimeError('expected at least 2 arguments')
  assert S_i['i'] == S_j['i']
  S_i = S_i.copy()
  S_j = S_j.copy()
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  if 'alpha' in S_j:
    pk = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
    sk = phe.PaillierPrivateKey(pk, S_i['p'], S_i['q'])
    S_i['alpha'] = sk.decrypt(phe.EncryptedNumber(pk, S_j['alpha'])) % q
    S_i['mu'] = sk.decrypt(phe.EncryptedNumber(pk, S_j['mu'])) % q
    del S_i['p']
    del S_i['q']
    del S_j['alpha']
    del S_j['mu']
  if 'k' in S_j:
    pk = phe.PaillierPublicKey(S_j['n'])
    k = phe.EncryptedNumber(pk, S_j['k'])
    # MtA $k_j, \gamma_i$.
    beta0 = random.SystemRandom().randint(1, pk.max_int)
    S_i['beta'] = -beta0 % q
    S_j['alpha'] = (S_i['gamma'] * k + pk.encrypt(beta0)).ciphertext()
    # MtA $k_j, w_i$.
    nu0 = random.SystemRandom().randint(1, pk.max_int)
    S_i['nu'] = -nu0 % q
    S_j['mu'] = (S_i['w'] * k + pk.encrypt(nu0)).ciphertext()
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

def sign_combine(shares):
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
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  # Check if combining $s$ shares.
  if 'r' in shares[0] and 's' in shares[0]:
    assert len(shares) > 1
    # Every r must match.
    r = shares[0]['r']
    assert reduce(
      lambda a, b: a and b,
      map(lambda share: share['r'] == r, shares[1:])
    )
    s = sum(map(lambda share: share['s'], shares)) % q
    # Normalize s.
    if s > q // 2:
      s = q - s
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
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  # Compute $\delta_i = k_i \gamma_i + \sum_{j \ne i} \alpha_{ij}
  #                                  + \sum_{j \ne i} \beta_{ji}$.
  delta = (P_i[0]['k'] * P_i[0]['gamma'] + sum(alpha) + sum(beta)) % q
  # Compute $\omicron_i = k_i \w_i + \sum_{j \ne i} \mu_{ij}
  #                                + \sum_{j \ne i} \nu_{ji}$.
  omicron = (P_i[0]['k'] * P_i[0]['w'] + sum(mu) + sum(nu)) % q
  Gamma = ecdsa.ecdsa.generator_secp256k1 * P_i[0]['gamma']
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

def sign(M, shares):
  """
  Sign a message.

  :param M: Message to sign.
  
  :type M: bytes

  :return: Signature share to be combined with all other signers' signature
    shares.

  :rtype: dict
  """
  H = hashlib.sha256()
  H.update(M)
  m = int.from_bytes(H.digest(), 'big')
  P_i = next(filter(lambda share: 'k' in share, shares))
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  delta = sum(map(lambda share: share['delta'], shares)) % q
  # Compute $R = [\Pi_{i \in S} \Gamma_i]^\delta^{-1}$ and $r = H'(R)$.
  R = reduce(
    lambda Gamma_i, Gamma_j: Gamma_i + Gamma_j,
    map(lambda share: share['Gamma'], shares),
    ecdsa.ellipticcurve.INFINITY,
  ) * pow(delta, -1, q)
  r = int(R.x())
  # Compute $s_i = m k_i + r \omicron_i$.
  s = (m * P_i['k'] + r * P_i['omicron']) % q
  return {
    'i': P_i['i'],
    'y': P_i['y'],
    'r': r,
    's': s,
  }

def verify(M, sig):
  """
  Verify a signature.

  :param M: Signed message.

  :type M: bytes

  :param sig: Signature.

  :type sig: dict

  :return: True if signature is valid; False otherwise.

  :rtype: bool
  """
  key = ecdsa.VerifyingKey.from_public_point(
    sig['y'],
    curve=ecdsa.curves.SECP256k1,
    hashfunc=hashlib.sha256,
  )
  compact = sig['r'].to_bytes(32, 'big') + sig['s'].to_bytes(32, 'big')
  try:
    return key.verify(compact, M)
  except ecdsa.keys.BadSignatureError:
    return False

def split(s, t, n):
  """
  Perform Shamir sharing on the secret `s` to the degree `t - 1` split `n`
  ways.

  The split secret requires `t` shares to be reconstructed.

  :param s: Secret to split.

  :type s: int

  :param t: Share threshold required to reconstruct secret.

  :type t: int

  :param n: Total number of shares to split secret into.

  :type n: int

  :return: Dictionary of shares. Each key is an int in the range 1<=x<=n
    representing that share's free term.

  :rtype dict:
  """
  assert t > 1
  assert t <= n
  q = int(ecdsa.ecdsa.generator_secp256k1.order())
  coefs = [random.SystemRandom().randrange(1, q) for i in range(0, t - 1)] + [s]
  shares = dict()
  for x in range(1, 1 + n):
    shares[x] = reduce(
      lambda partial, coef: (partial * x + coef) % q,
      coefs
    )
  return shares

def combine(shares):
  """
  Reconstitute a secret from a dictionary of shares.

  The number of shares must be equal to `t` to reconstitute the original secret.

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
        num *= xj
    denum = 1
    for xj in shares:
      if xi != xj:
        denum *= xj - xi
    s += num * pow(denum, -1, q) * yi
  return s % q
