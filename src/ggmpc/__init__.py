import hashlib, phe, random, secp256k1
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
  u = random.SystemRandom().randrange(1, q)
  y = g * u
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
    Point.infinity(),
  )
  # Add secret shares of $x$.
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
  k = random.SystemRandom().randrange(1, q)
  gamma = random.SystemRandom().randrange(1, q)
  # Map $x_i$ in $(n,t)$ to $w_i$ in $(t,t)$.
  d = reduce(
    lambda acc, S_j: acc * ((S_j['j'] - S_i['i']) % q),
    [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
  )
  n = reduce(
    lambda acc, S_j: acc * S_j['j'],
    [S_i['i']] + list(filter(lambda S_j: 'j' in S_j, S)),
  )
  w = (S_i['x'] * pow(d, -1, q) * n) % q
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
  # Compute $\delta_i = k_i \gamma_i + \sum_{j \ne i} \alpha_{ij}
  #                                  + \sum_{j \ne i} \beta_{ji}$.
  delta = (P_i[0]['k'] * P_i[0]['gamma'] + sum(alpha) + sum(beta)) % q
  # Compute $\omicron_i = k_i \w_i + \sum_{j \ne i} \mu_{ij}
  #                                + \sum_{j \ne i} \nu_{ji}$.
  omicron = (P_i[0]['k'] * P_i[0]['w'] + sum(mu) + sum(nu)) % q
  Gamma = g * P_i[0]['gamma']
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

def sign(m, shares):
  """
  Sign a message.

  :param m: Message to sign.
  
  :type m: int

  :return: Signature share to be combined with all other signers' signature
    shares.

  :rtype: dict
  """
  P_i = next(filter(lambda share: 'k' in share, shares))
  delta = sum(map(lambda share: share['delta'], shares)) % q
  # Compute $R = [\Pi_{i \in S} \Gamma_i]^\delta^{-1}$ and $r = H'(R)$.
  R = reduce(
    lambda Gamma_i, Gamma_j: Gamma_i + Gamma_j,
    map(lambda share: share['Gamma'], shares),
    Point.infinity(),
  ) * pow(delta, -1, q)
  r = R.x
  # Compute $s_i = m k_i + r \omicron_i$.
  s = (m * P_i['k'] + r * P_i['omicron']) % q
  return {
    'i': P_i['i'],
    'y': P_i['y'],
    'r': r,
    's': s,
  }

def verify(m, sig):
  """
  Verify a signature.

  :param m: Signed message.

  :type m: int

  :param sig: Signature.

  :type sig: dict

  :return: True if signature is valid; False otherwise.

  :rtype: bool
  """
  pk = secp256k1.PublicKey(sig['y'].to_bytes(), raw=True)
  compact = sig['r'].to_bytes(32, 'big') + sig['s'].to_bytes(32, 'big')
  sig = secp256k1.PublicKey().ecdsa_deserialize_compact(compact)
  return pk.ecdsa_verify(m.to_bytes(32, 'big'), sig, raw=True)

def serialize_int(x, length):
  """
  Serialize `x` to `length` number bytes.

  :param x: Integer to serialize.

  :type x: int

  :param length: Number of bytes returned.

  :type length: int

  :return: Serialization of `x`.

  :rtype: bytes
  """
  return x.to_bytes(length, 'big')

def deserialize_int(ser, length):
  """
  Deserialize a `length`-byte integer from `ser`.

  :param ser: Serialized data.

  :type ser: bytes

  :param length: Number of bytes to deserialize.

  :type length: int

  :return: The remainder of the serialized data and the deserialized integer.

  :rtype: tuple
  """
  x = int.from_bytes(ser[:length], 'big')
  ser = ser[length:]
  return ser, x

def serialize_point(p):
  """
  Serialize point.

  :param p: Point to serialize.

  :type x: Point

  :return: Serialization of `p`.

  :rtype: bytes
  """
  return p.to_bytes(compress=True)

def deserialize_point(ser):
  """
  Deserialize a point.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized point.

  :rtype: tuple
  """
  if ser[0] == 0x00:
    return ser[1:], Point.infinity()
  if ser[0] == 0x04:
    return ser[65:], Point.from_bytes(ser[:65])
  return ser[33:], Point.from_bytes(ser[:33])

def serialize_p_share(share):
  """
  Serialize a p-share.

  :param share: P-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['p'], 192)
  ser += serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['u'], 32)
  return ser

def deserialize_p_share(ser):
  """
  Deserialize a p-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized p-share.

  :rtype: tuple
  """
  P_i = {}
  ser, P_i['i'] = deserialize_int(ser, 1)
  ser, P_i['p'] = deserialize_int(ser, 192)
  ser, P_i['q'] = deserialize_int(ser, 192)
  ser, P_i['y'] = deserialize_point(ser)
  ser, P_i['u'] = deserialize_int(ser, 32)
  return ser, P_i

def serialize_n_share(share):
  """
  Serialize an n-share.

  :param share: N-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['n'], 384)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['u'], 32)
  return ser

def deserialize_n_share(ser):
  """
  Deserialize an n-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized n-share.

  :rtype: tuple
  """
  P_j = {}
  ser, P_j['i'] = deserialize_int(ser, 1)
  ser, P_j['j'] = deserialize_int(ser, 1)
  ser, P_j['n'] = deserialize_int(ser, 384)
  ser, P_j['y'] = deserialize_point(ser)
  ser, P_j['u'] = deserialize_int(ser, 32)
  return ser, P_j

def serialize_x_share(share):
  """
  Serialize an x-share.

  :param share: X-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['p'], 192)
  ser += serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['x'], 32)
  return ser

def deserialize_x_share(ser):
  """
  Deserialize an x-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized x-share.

  :rtype: tuple
  """
  P_i = {}
  ser, P_i['i'] = deserialize_int(ser, 1)
  ser, P_i['p'] = deserialize_int(ser, 192)
  ser, P_i['q'] = deserialize_int(ser, 192)
  ser, P_i['y'] = deserialize_point(ser)
  ser, P_i['x'] = deserialize_int(ser, 32)
  return ser, P_i

def serialize_y_share(share):
  """
  Serialize a y-share.

  :param share: Y-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['n'], 384)
  return ser

def deserialize_y_share(ser):
  """
  Deserialize a y-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized y-share.

  :rtype: tuple
  """
  P_j = {}
  ser, P_j['i'] = deserialize_int(ser, 1)
  ser, P_j['j'] = deserialize_int(ser, 1)
  ser, P_j['n'] = deserialize_int(ser, 384)
  return ser, P_j

def serialize_w_share(share):
  """
  Serialize a w-share.

  :param share: W-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['p'], 192)
  ser += serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['k'], 32)
  ser += serialize_int(share['w'], 32)
  ser += serialize_int(share['gamma'], 32)
  return ser

def deserialize_w_share(ser):
  """
  Deserialize a w-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized w-share.

  :rtype: tuple
  """
  S_i = {}
  ser, S_i['i'] = deserialize_int(ser, 1)
  ser, S_i['p'] = deserialize_int(ser, 192)
  ser, S_i['q'] = deserialize_int(ser, 192)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = deserialize_int(ser, 32)
  ser, S_i['w'] = deserialize_int(ser, 32)
  ser, S_i['gamma'] = deserialize_int(ser, 32)
  return ser, S_i

def serialize_k_share(share):
  """
  Serialize a k-share.

  :param share: K-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['n'], 384)
  ser += serialize_int(share['k'], 768)
  return ser

def deserialize_k_share(ser):
  """
  Deserialize a k-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized k-share.

  :rtype: tuple
  """
  S_j = {}
  ser, S_j['i'] = deserialize_int(ser, 1)
  ser, S_j['j'] = deserialize_int(ser, 1)
  ser, S_j['n'] = deserialize_int(ser, 384)
  ser, S_j['k'] = deserialize_int(ser, 768)
  return ser, S_j

def serialize_b_share(shares):
  """
  Serialize a beta-share.

  :param share: Beta-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  S_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  S_j = shares[next(filter(lambda j: 'j' in shares[j], shares))]
  ser = b''
  ser += serialize_int(S_i['i'], 1)
  ser += serialize_int(S_j['i'], 1)
  ser += serialize_int(S_i['p'], 192)
  ser += serialize_int(S_i['q'], 192)
  ser += serialize_point(S_i['y'])
  ser += serialize_int(S_i['k'], 32)
  ser += serialize_int(S_i['w'], 32)
  ser += serialize_int(S_i['gamma'], 32)
  ser += serialize_int(S_i['beta'], 32)
  ser += serialize_int(S_i['nu'], 32)
  ser += serialize_int(S_j['n'], 384)
  ser += serialize_int(S_j['k'], 768)
  ser += serialize_int(S_j['alpha'], 768)
  ser += serialize_int(S_j['mu'], 768)
  return ser

def deserialize_b_share(ser):
  """
  Deserialize a beta-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized beta-share.

  :rtype: tuple
  """
  S_i, S_j = {}, {}
  ser, S_i['i'] = deserialize_int(ser, 1)
  ser, S_j['i'] = deserialize_int(ser, 1)
  S_j['j'] = S_i['i']
  ser, S_i['p'] = deserialize_int(ser, 192)
  ser, S_i['q'] = deserialize_int(ser, 192)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = deserialize_int(ser, 32)
  ser, S_i['w'] = deserialize_int(ser, 32)
  ser, S_i['gamma'] = deserialize_int(ser, 32)
  ser, S_i['beta'] = deserialize_int(ser, 32)
  ser, S_i['nu'] = deserialize_int(ser, 32)
  ser, S_j['n'] = deserialize_int(ser, 384)
  ser, S_j['k'] = deserialize_int(ser, 768)
  ser, S_j['alpha'] = deserialize_int(ser, 768)
  ser, S_j['mu'] = deserialize_int(ser, 768)
  return ser, {
    S_i['i']: S_i,
    S_j['i']: S_j,
  }

def serialize_a_share(share):
  """
  Serialize an alpha-share.

  :param share: Alpha-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['n'], 384)
  ser += serialize_int(share['k'], 768)
  ser += serialize_int(share['alpha'], 768)
  ser += serialize_int(share['mu'], 768)
  return ser

def deserialize_a_share(ser):
  """
  Deserialize an alpha-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized w-share.

  :rtype: tuple
  """
  S_j = {}
  ser, S_j['i'] = deserialize_int(ser, 1)
  ser, S_j['j'] = deserialize_int(ser, 1)
  ser, S_j['n'] = deserialize_int(ser, 384)
  ser, S_j['k'] = deserialize_int(ser, 768)
  ser, S_j['alpha'] = deserialize_int(ser, 768)
  ser, S_j['mu'] = deserialize_int(ser, 768)
  return ser, S_j

def serialize_m_share(share):
  """
  Serialize a mu-share.

  :param share: Mu-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['alpha'], 768)
  ser += serialize_int(share['mu'], 768)
  return ser

def deserialize_m_share(ser):
  """
  Deserialize a mu-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized mu-share.

  :rtype: tuple
  """
  S_j = {}
  ser, S_j['i'] = deserialize_int(ser, 1)
  ser, S_j['j'] = deserialize_int(ser, 1)
  ser, S_j['alpha'] = deserialize_int(ser, 768)
  ser, S_j['mu'] = deserialize_int(ser, 768)
  return ser, S_j

def serialize_g_share(shares):
  """
  Serialize a gamma-share.

  :param share: Gamma-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  S_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  S_j = shares[next(filter(lambda j: 'j' in shares[j], shares))]
  ser = b''
  ser += serialize_int(S_i['i'], 1)
  ser += serialize_int(S_j['i'], 1)
  ser += serialize_point(S_i['y'])
  ser += serialize_int(S_i['k'], 32)
  ser += serialize_int(S_i['w'], 32)
  ser += serialize_int(S_i['gamma'], 32)
  ser += serialize_int(S_i['alpha'], 32)
  ser += serialize_int(S_i['beta'], 32)
  ser += serialize_int(S_i['mu'], 32)
  ser += serialize_int(S_i['nu'], 32)
  return ser

def deserialize_g_share(ser):
  """
  Deserialize a gamma-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized
    gamma-share.

  :rtype: tuple
  """
  S_i, S_j = {}, {}
  ser, S_i['i'] = deserialize_int(ser, 1)
  ser, S_j['i'] = deserialize_int(ser, 1)
  S_j['j'] = S_i['i']
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = deserialize_int(ser, 32)
  ser, S_i['w'] = deserialize_int(ser, 32)
  ser, S_i['gamma'] = deserialize_int(ser, 32)
  ser, S_i['alpha'] = deserialize_int(ser, 32)
  ser, S_i['beta'] = deserialize_int(ser, 32)
  ser, S_i['mu'] = deserialize_int(ser, 32)
  ser, S_i['nu'] = deserialize_int(ser, 32)
  return ser, {
    S_i['i']: S_i,
    S_j['i']: S_j,
  }

def serialize_o_share(share):
  """
  Serialize an omicron-share.

  :param share: Omicron-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['k'], 32)
  ser += serialize_int(share['omicron'], 32)
  ser += serialize_int(share['delta'], 32)
  ser += serialize_point(share['Gamma'])
  return ser

def deserialize_o_share(ser):
  """
  Deserialize a omicron-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized
    omicron-share.

  :rtype: tuple
  """
  S_i = {}
  ser, S_i['i'] = deserialize_int(ser, 1)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = deserialize_int(ser, 32)
  ser, S_i['omicron'] = deserialize_int(ser, 32)
  ser, S_i['delta'] = deserialize_int(ser, 32)
  ser, S_i['Gamma'] = deserialize_point(ser)
  return ser, S_i

def serialize_d_share(share):
  """
  Serialize a delta-share.

  :param share: Delta-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_int(share['j'], 1)
  ser += serialize_int(share['delta'], 32)
  ser += serialize_point(share['Gamma'])
  return ser
  
def deserialize_d_share(ser):
  """
  Deserialize a delta-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized
    delta-share.

  :rtype: tuple
  """
  S_j = {}
  ser, S_j['i'] = deserialize_int(ser, 1)
  ser, S_j['j'] = deserialize_int(ser, 1)
  ser, S_j['delta'] = deserialize_int(ser, 32)
  ser, S_j['Gamma'] = deserialize_point(ser)
  return ser, S_j

def serialize_s_share(share):
  """
  Serialize an s-share.

  :param share: S-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_int(share['i'], 1)
  ser += serialize_point(share['y'])
  ser += serialize_int(share['r'], 32)
  ser += serialize_int(share['s'], 32)
  return ser

def deserialize_s_share(ser):
  """
  Deserialize a s-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized s-share.

  :rtype: tuple
  """
  S_i = {}
  ser, S_i['i'] = deserialize_int(ser, 1)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['r'] = deserialize_int(ser, 32)
  ser, S_i['s'] = deserialize_int(ser, 32)
  return ser, S_i

def serialize_signature(signature):
  """
  Serialize a signature.

  :param signature: Signature to serialize.

  :type signature: dict

  :return: Serialization of `signature`.

  :rtype: bytes
  """
  ser = b''
  ser += serialize_point(signature['y'])
  ser += serialize_int(signature['r'], 32)
  ser += serialize_int(signature['s'], 32)
  return ser

def deserialize_signature(ser):
  """
  Deserialize a signature.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized signature.

  :rtype: tuple
  """
  sig = {}
  ser, sig['y'] = deserialize_point(ser)
  ser, sig['r'] = deserialize_int(ser, 32)
  ser, sig['s'] = deserialize_int(ser, 32)
  return ser, sig

def hash(M):
  """
  Returns a digest of the input message `M`.
  
  The output digest is at most as many bits in length as the order of 
  the curve.

  :param M: The input message.

  :type M: bytes

  :return: Digest of the input message `M`.

  :rtype: int
  """
  H = hashlib.sha256()
  H.update(M)
  return int.from_bytes(H.digest(), 'big')

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

class Point:

  def infinity():
    """
    Return point at infinity.

    :return: New point at infinity.

    :rtype: Point
    """
    return Point(None, None, inf=True)

  def from_bytes(ser):
    """
    Deserialize a point from an SEC formatted byte string.

    :param ser: An SEC formatted byte string.

    :type ser: bytes

    :return: Deserialized point.

    :rtype: Point
    """
    if ser[0] == 0x00:
      assert len(ser) == 1
      return Point.infinity()
    elif ser[0] == 0x04:
      assert len(ser) == 65
    else:
      assert ser[0] == 0x02 or ser[0] == 0x03
      assert len(ser) == 33
    p = secp256k1.PublicKey(ser, raw=True)
    p = p.serialize(compressed=False)
    return Point(int.from_bytes(p[1:33], 'big'), int.from_bytes(p[33:], 'big'))

  def __init__(self, x, y, inf=None):
    """ Construct new point at (x,y) or at infinity. """
    self.x = x
    self.y = y
    self.inf = inf

  def __add__(self, q):
    """
    Multiply point `p` (self) by `q`, peforming point addition of the two
    points.

    :param q: Point to add with.

    :type q: Point

    :return: New point `pq`.

    :rtype: Point
    """
    if self.inf:
      if q.inf:
        return Point.infinity()
      return q
    elif q.inf:
      return Point(self.x, self.y)
    import sys
    P = secp256k1.PublicKey(self.to_bytes(), raw=True)
    Q = secp256k1.PublicKey(q.to_bytes(), raw=True)
    R = secp256k1.PublicKey()
    R.combine([P.public_key, Q.public_key])
    return Point.from_bytes(R.serialize(compressed=False))

  def __mul__(self, x):
    """
    Raise point `p` (self) to `x', performing scalar multiplication of the
    original point.

    :param x: Scalar to raise the point by.

    :type x: int

    :return: New point `p^x`.

    :rtype: Point
    """
    P = secp256k1.PublicKey(self.to_bytes(), raw=True)
    P = P.tweak_mul(x.to_bytes(32, 'big'))
    return Point.from_bytes(P.serialize(compressed=False))

  def to_bytes(self, compress=False):
    """
    Serialize to SEC format byte string.

    :param compress: Flag to serialize as compressed point.

    :type compress: bool

    :return: Serialized point.

    :rtype: bytes
    """
    if self.inf:
      return b'\x00'
    if compress:
      return (2 + (self.y % 2)).to_bytes(1, 'big') + self.x.to_bytes(32, 'big')
    return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')

q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
""" The order of the curve. """

g = Point(
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)
""" The curve generator. """
