""" Supported elliptic curves. """

import ecdsa, hashlib, random
from nacl import bindings

class Curve:
  """
  Elliptic curve parameters.

  :param scalar_random: Function that returns a random field element.

  :type scalar_random: function

  :param scalar_add: Function that returns the sum of two field elements modulo
    the order of the curve.

  :type scalar_add: function

  :param scalar_sub: Function that returns the difference of two field elements
    modulo the order of the curve.

  :type scalar_sub: function

  :param scalar_mul: Function that returns the product of two field elements
    modulo the order of the curve.

  :type scalar_mul: function

  :param scalar_reduce: Function that reduces a scalar modulo the order of the
    curve.

  :type scalar_reduce: function

  :param scalar_invert: Function that returns the modular multiplicative inverse
    of a field element.

  :type scalar_invert: function

  :param scalar_negate: Function that returns the negated field element modulo
    the order of the curve.

  :type scalar_negate: function

  :param point_add: Function that adds two group elements.

  :type point_add: function

  :param point_mul: Function that multiplies a group element by a field element.

  :type point_mul: function

  :param point_mul_base: Function that multiplies the curve generator by a field
    element.

  :type point_mul_base: function

  :param order: Function that returns the order of the curve.

  :type order: function

  :param hash: A hash function using a `hashlib`-like interface.

  :type hash: function

  :param verify: Function that verifies a signature.

  :type verify: function
  """

  def __init__(
      self,
      scalar_random,
      scalar_add,
      scalar_sub,
      scalar_mul,
      scalar_reduce,
      scalar_negate,
      scalar_invert,
      point_add,
      point_mul,
      point_mul_base,
      order,
      hash,
      verify,
  ):
    self.scalar_random = scalar_random
    self.scalar_add = scalar_add
    self.scalar_sub = scalar_sub
    self.scalar_mul = scalar_mul
    self.scalar_reduce = scalar_reduce
    self.scalar_negate = scalar_negate
    self.scalar_invert = scalar_invert
    self.point_add = point_add
    self.point_mul = point_mul
    self.point_mul_base = point_mul_base
    self.order = order
    self.hash = hash
    self.verify = verify

def _ecdsa_verify(curve, hash):
  return lambda y, M, sig: ecdsa.VerifyingKey.from_public_point(
    y,
    curve=curve,
    hashfunc=hash,
  ).verify(sig, M)

_secp256k1_order = int(ecdsa.ecdsa.generator_secp256k1.order())

secp256k1 = Curve(
  lambda: random.SystemRandom().randrange(1, _secp256k1_order),
  lambda a, b: (a + b) % _secp256k1_order,
  lambda a, b: (a - b) % _secp256k1_order,
  lambda a, b: (a * b) % _secp256k1_order,
  lambda x: x % _secp256k1_order,
  lambda x: -x % _secp256k1_order,
  lambda x: pow(x, -1, _secp256k1_order),
  lambda p, q: p + q,
  lambda p, q: p * q,
  lambda n: ecdsa.ecdsa.generator_secp256k1 * n,
  lambda: _secp256k1_order,
  hashlib.sha256,
  _ecdsa_verify(ecdsa.curves.SECP256k1, hashlib.sha256),
)
""" Secp256k1 ECDSA curve. """

ed25519 = Curve(
  lambda: int.from_bytes(bindings.crypto_core_ed25519_scalar_reduce(
    random.SystemRandom().randrange(1, 2 ** 512).to_bytes(64, 'little'),
  ), 'little'),
  lambda a, b: int.from_bytes(bindings.crypto_core_ed25519_scalar_add(
    a.to_bytes(32, 'little'),
    b.to_bytes(32, 'little'),
  ), 'little'),
  lambda a, b: int.from_bytes(bindings.crypto_core_ed25519_scalar_sub(
    a.to_bytes(32, 'little'),
    b.to_bytes(32, 'little'),
  ), 'little'),
  lambda a, b: int.from_bytes(bindings.crypto_core_ed25519_scalar_mul(
    a.to_bytes(32, 'little'),
    b.to_bytes(32, 'little'),
  ), 'little'),
  lambda x: int.from_bytes(bindings.crypto_core_ed25519_scalar_reduce(
    x.to_bytes(64, 'little'),
  ), 'little'),
  lambda x: int.from_bytes(bindings.crypto_core_ed25519_scalar_negate(
    x.to_bytes(32, 'little'),
  ), 'little'),
  lambda x: int.from_bytes(bindings.crypto_core_ed25519_scalar_invert(
    x.to_bytes(32, 'little'),
  ), 'little'),
  lambda p, q: int.from_bytes(bindings.crypto_core_ed25519_add(
    p.to_bytes(32, 'little'),
    q.to_bytes(32, 'little'),
  ), 'little'),
  lambda p, n: int.from_bytes(bindings.crypto_scalarmult_ed25519_noclamp(
    p.to_bytes(32, 'little'),
    n.to_bytes(32, 'little'),
  ), 'little'),
  lambda n: int.from_bytes(bindings.crypto_scalarmult_ed25519_base_noclamp(
    n.to_bytes(32, 'little'),
  ), 'little'),
  None,
  hashlib.sha512,
  lambda y, M, sig: bindings.crypto_sign_open(sig + M, y)
)
""" Ed25519 EdDSA curve. """
