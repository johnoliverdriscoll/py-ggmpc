""" ECDSA threshold signing library. """

import hashlib
import phe
from functools import reduce
from . import shamir
from .rand import get_random_less_than, get_random_coprime_to

MODULUS_BITS = 3072

class Ecdsa:
  """
  Threshold signing over the ECDSA cryptosystem.

  :param curve: The ECDSA curve to use.

  :type curve: ggmpc.Curve
  """

  def __init__(self, curve):
    self.curve = curve

  def secret_generate(self):
    """
    Generate a secret that can be used as a contribution in DKG.

    :return: A secret.

    :rtype: int
    """
    return self.curve.scalar_random()

  def key_share(self, i, t, n, u=None):
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
    pk, sk = phe.generate_paillier_keypair(n_length=MODULUS_BITS)
    # Generate $u_i \in_R \Z_q$.
    if not u:
      u = self.curve.scalar_random()
    # Compute secret shares of their $u_i$.
    u = shamir.split(self.curve, u, t, n)
    v = u['v']
    y = v[0]
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

    :return: Dictionary of shares. Share at player's index is a private x-share.
      Other indices are y-shares to be used when generating signing shares.

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
        }
    return players

  def sign_challenge(self, S):
    """
    Create a challenge that another signer uses to prove their
    nonce contributions during MtA conversion.

    :param S: Tuple of shares for each signer. Must include player's private
      x-share and y-shares received from all other signers.

    :type S: tuple

    :return: Dictionary of shares. Share at signer's index is a private h-share.
      Other indices are j-shares to be distributed to signers at their
      corresponding index.

    :rtype: dict
    """
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    ntilde, h1, h2 = generate_pre_params()
    signers = {
      S_i['i']: {
        'i': S_i['i'],
        'p': S_i['p'],
        'q': S_i['q'],
        'ntilde': ntilde,
        'h1': h1,
        'h2': h2,
        'y': S_i['y'],
        'x': S_i['x'],
      }
    }
    for S_j in S:
      if 'j' in S_j:
        signers[S_j['j']] = {
          'i': S_j['j'],
          'j': S_i['i'],
          'n': S_i['p'] * S_i['q'],
          'ntilde': ntilde,
          'h1': h1,
          'h2': h2,
        }
    return signers

  def sign_share(self, S):
    """
    Create signing shares.

    :param S: Tuple of shares for each signer. Must include either:

      * The signer's private h-share and j-shares received from all other signers.

      * The signer's private x-share and j-shares received from all other signers.

    :type S: tuple

    :return: Dictionary of shares. Share at signer's index is a private w-share.
      Other indices are k-shares to be distributed to signers at their
      corresponding index.

    :rtype: dict
    """
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    if not 'ntilde' in S_i:
      S_i = self.sign_challenge(S)[S_i['i']]
    pka = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
    # Select $k_i, \gamma_i \in_R Z_q$.
    k = self.curve.scalar_random()
    rk = get_random_coprime_to(pka.n)
    ck = pka.encrypt(k, r_value=rk).ciphertext(False)
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
    # Generate pre params.
    ntildea, h1a, h2a = S_i['ntilde'], S_i['h1'], S_i['h2']
    signers = {
      S_i['i']: {
        'i': S_i['i'],
        'p': S_i['p'],
        'q': S_i['q'],
        'y': S_i['y'],
        'ntilde': ntildea,
        'h1': h1a,
        'h2': h2a,
        'k': k,
        'ck': ck,
        'rk': rk,
        'w': w,
        'gamma': gamma,
      },
    }
    for S_j in S:
      if 'j' in S_j:
        # Prove $k_i \in Z_{N^2}$.
        ntildeb, h1b, h2b = S_j['ntilde'], S_j['h1'], S_j['h2']
        z, u, w, s, s1, s2 = prove_range(self.curve, pka, ck, ntildeb, h1b, h2b, k, rk)
        signers[S_j['j']] = {
          'i': S_j['j'],
          'j': S_i['i'],
          'n': pka.n,
          'ntilde': ntildea,
          'h1': h1a,
          'h2': h2a,
          'k': ck,
          'z': z,
          'u': u,
          'w': w,
          's': s,
          's1': s1,
          's2': s2,
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

      * The signer's private w-share and the alpha-share received from the other
        signer.

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
    S_i = next(filter(lambda S_i: not 'j' in S_i, S))
    if 'x' in S_i:
      S_i = self.sign_share(S)[S_i['i']]
    S_j = next(filter(lambda S_j: 'j' in S_j, S))
    assert S_i['i'] == S_j['i']
    S_i = S_i.copy()
    S_j = S_j.copy()
    if 'alpha' in S_j:
      pka = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
      ntildea = S_i['ntilde']
      h1a = S_i['h1']
      h2a = S_i['h2']
      # Verify $\gamma_i \in Z_{N^2}$.
      gz = S_j['gz']
      gzprm = S_j['gzprm']
      gt = S_j['gt']
      gv = S_j['gv']
      gw = S_j['gw']
      gs = S_j['gs']
      gs1 = S_j['gs1']
      gs2 = S_j['gs2']
      gt1 = S_j['gt1']
      gt2 = S_j['gt2']
      gu = S_j['gu']
      gx = S_j['gx']
      if not verify_range_proof_wc(
          self.curve,
          pka,
          ntildea,
          h1a,
          h2a,
          gz,
          gzprm,
          gt,
          gv,
          gw,
          gs,
          gs1,
          gs2,
          gt1,
          gt2,
          S_i['ck'],
          S_j['alpha'],
          gu,
          gx,
      ):
        raise RuntimeError('could not verify share')
      # Verify $\w_i \in Z_{N^2}$.
      wz = S_j['wz']
      wzprm = S_j['wzprm']
      wt = S_j['wt']
      wv = S_j['wv']
      ww = S_j['ww']
      ws = S_j['ws']
      ws1 = S_j['ws1']
      ws2 = S_j['ws2']
      wt1 = S_j['wt1']
      wt2 = S_j['wt2']
      wu = S_j['wu']
      wx = S_j['wx']
      if not verify_range_proof_wc(
          self.curve,
          pka,
          ntildea,
          h1a,
          h2a,
          wz,
          wzprm,
          wt,
          wv,
          ww,
          ws,
          ws1,
          ws2,
          wt1,
          wt2,
          S_i['ck'],
          S_j['mu'],
          wu,
          wx,
      ):
        raise RuntimeError('could not verify share')
      sk = phe.PaillierPrivateKey(pka, S_i['p'], S_i['q'])
      alpha = sk.decrypt(phe.EncryptedNumber(pka, S_j['alpha']))
      S_i['alpha'] = self.curve.scalar_reduce(alpha)
      mu = sk.decrypt(phe.EncryptedNumber(pka, S_j['mu']))
      S_i['mu'] = self.curve.scalar_reduce(mu)
      S_i['j'] = S_j['j']
      del S_i['p']
      del S_i['q']
      del S_j['alpha']
      del S_j['mu']
    if 'k' in S_j:
      pka = phe.PaillierPublicKey(S_j['n'])
      ntildea = S_j['ntilde']
      h1a = S_j['h1']
      h2a = S_j['h2']
      ntildeb = S_i['ntilde']
      h1b = S_i['h1']
      h2b = S_i['h2']
      z = S_j['z']
      u = S_j['u']
      w = S_j['w']
      s = S_j['s']
      s1 = S_j['s1']
      s2 = S_j['s2']
      k = S_j['k']
      if not verify_range_proof(self.curve, pka, ntildeb, h1b, h2b, z, u, w, s, s1, s2, k):
        raise RuntimeError('could not verify share')
      k = phe.EncryptedNumber(pka, k)
      # MtA $k_j, \gamma_i$.
      beta0 = get_random_less_than(pka.max_int)
      S_i['beta'] = self.curve.scalar_negate(self.curve.scalar_reduce(beta0))
      rb = get_random_coprime_to(pka.n)
      cb = pka.encrypt(beta0, r_value=rb)
      cg = S_i['gamma'] * k
      alpha = cg + cb
      S_j['alpha'] = alpha.ciphertext(False)
      # Prove $\gamma_i \in Z_{N^2}$.
      gx = self.curve.scalar_mul_base(S_i['gamma'])
      gz, gzprm, gt, gv, gw, gs, gs1, gs2, gt1, gt2, gu = prove_range_wc(
        self.curve,
        pka,
        ntildea,
        h1a,
        h2a,
        S_j['k'],
        S_j['alpha'],
        S_i['gamma'],
        beta0,
        rb,
        gx,
      )
      S_j['gz'] = gz
      S_j['gzprm'] = gzprm
      S_j['gt'] = gt
      S_j['gv'] = gv
      S_j['gw'] = gw
      S_j['gs'] = gs
      S_j['gs1'] = gs1
      S_j['gs2'] = gs2
      S_j['gt1'] = gt1
      S_j['gt2'] = gt2
      S_j['gu'] = gu
      S_j['gx'] = gx
      # MtA $k_j, w_i$.
      nu0 = get_random_less_than(pka.max_int)
      S_i['nu'] = self.curve.scalar_negate(self.curve.scalar_reduce(nu0))
      rn = get_random_coprime_to(pka.n)
      cn = pka.encrypt(nu0, r_value=rn)
      cw = S_i['w'] * k
      mu = cw + cn
      S_j['mu'] = mu.ciphertext(False)
      # Prove $\w_i \in Z_{N^2}$.
      wx = self.curve.scalar_mul_base(S_i['w'])
      wz, wzprm, wt, wv, ww, ws, ws1, ws2, wt1, wt2, wu = prove_range_wc(
        self.curve,
        pka,
        ntildea,
        h1a,
        h2a,
        S_j['k'],
        S_j['mu'],
        S_i['w'],
        nu0,
        rn,
        wx,
      )
      S_j['wz'] = wz
      S_j['wzprm'] = wzprm
      S_j['wt'] = wt
      S_j['wv'] = wv
      S_j['ww'] = ww
      S_j['ws'] = ws
      S_j['ws1'] = ws1
      S_j['ws2'] = ws2
      S_j['wt1'] = wt1
      S_j['wt2'] = wt2
      S_j['wu'] = wu
      S_j['wx'] = wx
      if 'alpha' in S_i:
        del S_i['ntilde']
        del S_i['h1']
        del S_i['h2']
        del S_i['ck']
        del S_i['rk']
        del S_j['n']
        del S_j['ntilde']
        del S_j['h1']
        del S_j['h2']
        del S_j['k']
      else:
        pkb = phe.PaillierPublicKey(S_i['p'] * S_i['q'])
        k = S_i['k']
        ck = S_i['ck']
        rk = S_i['rk']
        z, u, w, s, s1, s2 = prove_range(self.curve, pkb, ck, ntildea, h1a, h2a, k, rk)
        S_j['n'] = pkb.n
        S_j['ntilde'] = ntildeb
        S_j['h1'] = h1b
        S_j['h2'] = h2b
        S_j['k'] = ck
        S_j['z'] = z
        S_j['u'] = u
        S_j['w'] = w
        S_j['s'] = s
        S_j['s1'] = s1
        S_j['s2'] = s2
        del S_i['rk']
    if not 'alpha' in S_j and not 'k' in S_j:
      S_i['j'] = S_j['j']
      del S_i['ntilde']
      del S_i['h1']
      del S_i['h2']
      del S_i['ck']
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
    flat = []
    for share in shares:
      if reduce(lambda acc, key: acc and type(key) == int, share.keys(), True):
        flat += list(share.values())
      else:
        flat.append(share)
    P_i = []
    S = set()
    for share in flat:
      if 'gamma' in share:
        P_i.append(share)
        S.add(share['j'])
      else:
        S.add(share['i'])
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
    Gamma = self.curve.scalar_mul_base(P_i[0]['gamma'])
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

def to_bytes(x, byteorder):
  byte_length = max(1, (x.bit_length() + 7) // 8)
  return x.to_bytes(byte_length, byteorder)

def generate_pre_params():
  pk, _ = phe.generate_paillier_keypair(n_length=MODULUS_BITS)
  ntilde = pk.n
  pk, _ = phe.generate_paillier_keypair(n_length=MODULUS_BITS)
  f1 = get_random_coprime_to(ntilde)
  alpha = get_random_coprime_to(ntilde)
  beta = pow(alpha, -1, pk.n)
  h1 = pow(f1, 2, ntilde)
  h2 = pow(h1, alpha, ntilde)
  return (ntilde, h1, h2)

def prove_range(curve, pk, c, ntilde, h1, h2, m, r):
  q = curve.order()
  q3 = q ** 3
  qntilde = q * ntilde
  q3ntilde = q3 * ntilde
  alpha = get_random_less_than(q3)
  beta = get_random_coprime_to(pk.n)
  gamma = get_random_less_than(q3ntilde)
  rho = get_random_less_than(qntilde)
  z = (pow(h1, m, ntilde) * pow(h2, rho, ntilde)) % ntilde
  u = (pow(pk.g, alpha, pk.nsquare) * pow(beta, pk.n, pk.nsquare)) % pk.nsquare
  w = (pow(h1, alpha, ntilde) * pow(h2, gamma, ntilde)) % ntilde
  hash = hashlib.new('sha512_256')
  hash.update(b'\x06\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
    to_bytes(pk.n, 'big'),
    to_bytes(pk.g, 'big'),
    to_bytes(c, 'big'),
    to_bytes(z, 'big'),
    to_bytes(u, 'big'),
    to_bytes(w, 'big'),
  ]) + b'$')
  e = int.from_bytes(hash.digest(), 'big') % q
  s = (pow(r, e, pk.n) * beta) % pk.n
  s1 = e * m + alpha
  s2 = e * rho + gamma
  return (z, u, w, s, s1, s2)

def verify_range_proof(curve, pk, ntilde, h1, h2, z, u, w, s, s1, s2, c):
  q = curve.order()
  q3 = q ** 3
  if s1 == q3:
    return False
  hash = hashlib.new('sha512_256')
  hash.update(b'\x06\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
    to_bytes(pk.n, 'big'),
    to_bytes(pk.g, 'big'),
    to_bytes(c, 'big'),
    to_bytes(z, 'big'),
    to_bytes(u, 'big'),
    to_bytes(w, 'big'),
  ]) + b'$')
  e = int.from_bytes(hash.digest(), 'big') % q
  products = (pow(pk.g, s1, pk.nsquare) * pow(s, pk.n, pk.nsquare) * pow(c, -e, pk.nsquare)) % pk.nsquare
  if not u == products:
    return False
  products = (((pow(h1, s1, ntilde) * pow(h2, s2, ntilde)) % ntilde) * pow(z, -e, ntilde)) % ntilde
  if not w == products:
    return False
  return True

def prove_range_wc(curve, pk, ntilde, h1, h2, c1, c2, x, y, r, X):
  q = curve.order()
  q3 = q ** 3
  qntilde = q * ntilde
  q3ntilde = q3 * ntilde
  alpha = get_random_less_than(q3)
  rho = get_random_less_than(qntilde)
  sigma = get_random_less_than(qntilde)
  tau = get_random_less_than(qntilde)
  rhoprm = get_random_less_than(q3ntilde)
  beta = get_random_coprime_to(pk.n)
  gamma = get_random_less_than(q3ntilde)
  if X:
    u = curve.scalar_mul_base(alpha)
  z = (pow(h1, x, ntilde) * pow(h2, rho, ntilde)) % ntilde
  zprm = (pow(h1, alpha, ntilde) * pow(h2, rhoprm, ntilde)) % ntilde
  t = (pow(h1, y, ntilde) * pow(h2, sigma, ntilde)) % ntilde
  v = (((pow(c1, alpha, pk.nsquare) * pow(pk.g, gamma, pk.nsquare)) % pk.nsquare) * pow(beta, pk.n, pk.nsquare)) % pk.nsquare
  w = (pow(h1, gamma, ntilde) * pow(h2, tau, ntilde)) % ntilde
  if not X:
    hash = hashlib.new('sha512_256')
    hash.update(b'\x09\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
      to_bytes(pk.n, 'big'),
      to_bytes(pk.g, 'big'),
      to_bytes(c1, 'big'),
      to_bytes(c2, 'big'),
      to_bytes(z, 'big'),
      to_bytes(zprm, 'big'),
      to_bytes(t, 'big'),
      to_bytes(v, 'big'),
      to_bytes(w, 'big'),
    ]) + b'$')
    e = int.from_bytes(hash.digest(), 'big') % q
  else:
    hash = hashlib.new('sha512_256')
    hash.update(b'\x0d\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
      to_bytes(pk.n, 'big'),
      to_bytes(pk.g, 'big'),
      to_bytes(int(X.x().digits()), 'big'),
      to_bytes(int(X.y().digits()), 'big'),
      to_bytes(c1, 'big'),
      to_bytes(c2, 'big'),
      to_bytes(int(u.x().digits()), 'big'),
      to_bytes(int(u.y().digits()), 'big'),
      to_bytes(z, 'big'),
      to_bytes(zprm, 'big'),
      to_bytes(t, 'big'),
      to_bytes(v, 'big'),
      to_bytes(w, 'big'),
    ]) + b'$')
    e = int.from_bytes(hash.digest(), 'big') % q
  s = (pow(r, e, pk.n) * beta) % pk.n
  s1 = e * x + alpha
  s2 = e * rho + rhoprm
  t1 = e * y + gamma
  t2 = e * sigma + tau
  return (z, zprm, t, v, w, s, s1, s2, t1, t2, u)

def verify_range_proof_wc(curve, pk, ntilde, h1, h2, z, zprm, t, v, w, s, s1, s2, t1, t2, c1, c2, u, X):
  q = curve.order()
  q3 = q ** 3
  if s1 == q3:
    return False
  if not X:
    hash = hashlib.new('sha512_256')
    hash.update(b'\x09\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
      to_bytes(pk.n, 'big'),
      to_bytes(pk.g, 'big'),
      to_bytes(c1, 'big'),
      to_bytes(c2, 'big'),
      to_bytes(z, 'big'),
      to_bytes(zprm, 'big'),
      to_bytes(t, 'big'),
      to_bytes(v, 'big'),
      to_bytes(w, 'big'),
    ]) + b'$')
    e = int.from_bytes(hash.digest(), 'big') % q
  else:
    hash = hashlib.new('sha512_256')
    hash.update(b'\x0d\x00\x00\x00\x00\x00\x00\x00' + b'$'.join([
      to_bytes(pk.n, 'big'),
      to_bytes(pk.g, 'big'),
      to_bytes(int(X.x().digits()), 'big'),
      to_bytes(int(X.y().digits()), 'big'),
      to_bytes(c1, 'big'),
      to_bytes(c2, 'big'),
      to_bytes(int(u.x().digits()), 'big'),
      to_bytes(int(u.y().digits()), 'big'),
      to_bytes(z, 'big'),
      to_bytes(zprm, 'big'),
      to_bytes(t, 'big'),
      to_bytes(v, 'big'),
      to_bytes(w, 'big'),
    ]) + b'$')
    e = int.from_bytes(hash.digest(), 'big') % q
  if X:
    gS1 = curve.scalar_mul_base(curve.scalar_reduce(s1))
    xEU = X * e + u
    if not gS1 == xEU:
      return False
  h1ExpS1 = pow(h1, s1, ntilde)
  h2ExpS2 = pow(h2, s2, ntilde)
  left = (h1ExpS1 * h2ExpS2) % ntilde
  zExpE = pow(z, e, ntilde)
  right = (zExpE * zprm) % ntilde
  if not left == right:
    return False
  h1ExpT1 = pow(h1, t1, ntilde)
  h2ExpT2 = pow(h2, t2, ntilde)
  left = (h1ExpT1 * h2ExpT2) % ntilde
  tExpE = pow(t, e, ntilde)
  right = (tExpE * w) % ntilde
  if not left == right:
    return False
  c1ExpS1 = pow(c1, s1, pk.nsquare)
  sExpN = pow(s, pk.n, pk.nsquare)
  gammaExpT1 = pow(pk.g, t1, pk.nsquare)
  left = (((c1ExpS1 * sExpN) % pk.nsquare) * gammaExpT1) % pk.nsquare
  c2ExpE = pow(c2, e, pk.nsquare)
  right = (c2ExpE * v) % pk.nsquare
  if not left == right:
    return False
  return True
