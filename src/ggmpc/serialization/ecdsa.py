""" Serialization functions for ECDSA data. """

import ecdsa

from .. import serialization

def serialize_point(p):
  """
  Serialize point.

  :param p: Point to serialize.

  :type x: ecdsa.ellipticcurve.PointJacobi

  :return: Serialization of `p`.

  :rtype: bytes
  """
  return p.to_bytes(encoding='compressed')

def deserialize_point(ser):
  """
  Deserialize a point.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized point.

  :rtype: tuple
  """
  if ser[0] == 0x00:
    return ser[1:], ecdsa.ellipticcurve.INFINITY
  if ser[0] == 0x04:
    return ser[65:], ecdsa.ellipticcurve.PointJacobi.from_bytes(
      ecdsa.ecdsa.curve_secp256k1,
      ser[:65],
    )
  return ser[33:], ecdsa.ellipticcurve.PointJacobi.from_bytes(
    ecdsa.ecdsa.curve_secp256k1,
    ser[:33],
  )

def serialize_p_share(share):
  """
  Serialize a p-share.

  :param share: P-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['p'], 192)
  ser += serialization.serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['u'], 32)
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
  ser, P_i['i'] = serialization.deserialize_int(ser, 1)
  ser, P_i['p'] = serialization.deserialize_int(ser, 192)
  ser, P_i['q'] = serialization.deserialize_int(ser, 192)
  ser, P_i['y'] = deserialize_point(ser)
  ser, P_i['u'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['n'], 384)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['u'], 32)
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
  ser, P_j['i'] = serialization.deserialize_int(ser, 1)
  ser, P_j['j'] = serialization.deserialize_int(ser, 1)
  ser, P_j['n'] = serialization.deserialize_int(ser, 384)
  ser, P_j['y'] = deserialize_point(ser)
  ser, P_j['u'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['p'], 192)
  ser += serialization.serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['x'], 32)
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
  ser, P_i['i'] = serialization.deserialize_int(ser, 1)
  ser, P_i['p'] = serialization.deserialize_int(ser, 192)
  ser, P_i['q'] = serialization.deserialize_int(ser, 192)
  ser, P_i['y'] = deserialize_point(ser)
  ser, P_i['x'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['n'], 384)
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
  ser, P_j['i'] = serialization.deserialize_int(ser, 1)
  ser, P_j['j'] = serialization.deserialize_int(ser, 1)
  ser, P_j['n'] = serialization.deserialize_int(ser, 384)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['p'], 192)
  ser += serialization.serialize_int(share['q'], 192)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['k'], 32)
  ser += serialization.serialize_int(share['w'], 32)
  ser += serialization.serialize_int(share['gamma'], 32)
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
  ser, S_i['i'] = serialization.deserialize_int(ser, 1)
  ser, S_i['p'] = serialization.deserialize_int(ser, 192)
  ser, S_i['q'] = serialization.deserialize_int(ser, 192)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = serialization.deserialize_int(ser, 32)
  ser, S_i['w'] = serialization.deserialize_int(ser, 32)
  ser, S_i['gamma'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['n'], 384)
  ser += serialization.serialize_int(share['k'], 768)
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
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['j'] = serialization.deserialize_int(ser, 1)
  ser, S_j['n'] = serialization.deserialize_int(ser, 384)
  ser, S_j['k'] = serialization.deserialize_int(ser, 768)
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
  ser += serialization.serialize_int(S_i['i'], 1)
  ser += serialization.serialize_int(S_j['i'], 1)
  ser += serialization.serialize_int(S_i['p'], 192)
  ser += serialization.serialize_int(S_i['q'], 192)
  ser += serialize_point(S_i['y'])
  ser += serialization.serialize_int(S_i['k'], 32)
  ser += serialization.serialize_int(S_i['w'], 32)
  ser += serialization.serialize_int(S_i['gamma'], 32)
  ser += serialization.serialize_int(S_i['beta'], 32)
  ser += serialization.serialize_int(S_i['nu'], 32)
  ser += serialization.serialize_int(S_j['n'], 384)
  ser += serialization.serialize_int(S_j['k'], 768)
  ser += serialization.serialize_int(S_j['alpha'], 768)
  ser += serialization.serialize_int(S_j['mu'], 768)
  return ser

def deserialize_b_share(ser):
  """
  Deserialize a beta-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized
     beta-share.

  :rtype: tuple
  """
  S_i, S_j = {}, {}
  ser, S_i['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  S_j['j'] = S_i['i']
  ser, S_i['p'] = serialization.deserialize_int(ser, 192)
  ser, S_i['q'] = serialization.deserialize_int(ser, 192)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = serialization.deserialize_int(ser, 32)
  ser, S_i['w'] = serialization.deserialize_int(ser, 32)
  ser, S_i['gamma'] = serialization.deserialize_int(ser, 32)
  ser, S_i['beta'] = serialization.deserialize_int(ser, 32)
  ser, S_i['nu'] = serialization.deserialize_int(ser, 32)
  ser, S_j['n'] = serialization.deserialize_int(ser, 384)
  ser, S_j['k'] = serialization.deserialize_int(ser, 768)
  ser, S_j['alpha'] = serialization.deserialize_int(ser, 768)
  ser, S_j['mu'] = serialization.deserialize_int(ser, 768)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['n'], 384)
  ser += serialization.serialize_int(share['k'], 768)
  ser += serialization.serialize_int(share['alpha'], 768)
  ser += serialization.serialize_int(share['mu'], 768)
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
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['j'] = serialization.deserialize_int(ser, 1)
  ser, S_j['n'] = serialization.deserialize_int(ser, 384)
  ser, S_j['k'] = serialization.deserialize_int(ser, 768)
  ser, S_j['alpha'] = serialization.deserialize_int(ser, 768)
  ser, S_j['mu'] = serialization.deserialize_int(ser, 768)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['alpha'], 768)
  ser += serialization.serialize_int(share['mu'], 768)
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
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['j'] = serialization.deserialize_int(ser, 1)
  ser, S_j['alpha'] = serialization.deserialize_int(ser, 768)
  ser, S_j['mu'] = serialization.deserialize_int(ser, 768)
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
  ser += serialization.serialize_int(S_i['i'], 1)
  ser += serialization.serialize_int(S_j['i'], 1)
  ser += serialize_point(S_i['y'])
  ser += serialization.serialize_int(S_i['k'], 32)
  ser += serialization.serialize_int(S_i['w'], 32)
  ser += serialization.serialize_int(S_i['gamma'], 32)
  ser += serialization.serialize_int(S_i['alpha'], 32)
  ser += serialization.serialize_int(S_i['beta'], 32)
  ser += serialization.serialize_int(S_i['mu'], 32)
  ser += serialization.serialize_int(S_i['nu'], 32)
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
  ser, S_i['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  S_j['j'] = S_i['i']
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = serialization.deserialize_int(ser, 32)
  ser, S_i['w'] = serialization.deserialize_int(ser, 32)
  ser, S_i['gamma'] = serialization.deserialize_int(ser, 32)
  ser, S_i['alpha'] = serialization.deserialize_int(ser, 32)
  ser, S_i['beta'] = serialization.deserialize_int(ser, 32)
  ser, S_i['mu'] = serialization.deserialize_int(ser, 32)
  ser, S_i['nu'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['k'], 32)
  ser += serialization.serialize_int(share['omicron'], 32)
  ser += serialization.serialize_int(share['delta'], 32)
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
  ser, S_i['i'] = serialization.deserialize_int(ser, 1)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['k'] = serialization.deserialize_int(ser, 32)
  ser, S_i['omicron'] = serialization.deserialize_int(ser, 32)
  ser, S_i['delta'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['delta'], 32)
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
  ser, S_j['i'] = serialization.deserialize_int(ser, 1)
  ser, S_j['j'] = serialization.deserialize_int(ser, 1)
  ser, S_j['delta'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialize_point(share['y'])
  ser += serialization.serialize_int(share['r'], 32)
  ser += serialization.serialize_int(share['s'], 32)
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
  ser, S_i['i'] = serialization.deserialize_int(ser, 1)
  ser, S_i['y'] = deserialize_point(ser)
  ser, S_i['r'] = serialization.deserialize_int(ser, 32)
  ser, S_i['s'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(signature['r'], 32)
  ser += serialization.serialize_int(signature['s'], 32)
  return ser

def deserialize_signature(ser):
  """
  Deserialize a signature.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized
     signature.

  :rtype: tuple
  """
  sig = {}
  ser, sig['y'] = deserialize_point(ser)
  ser, sig['r'] = serialization.deserialize_int(ser, 32)
  ser, sig['s'] = serialization.deserialize_int(ser, 32)
  return ser, sig
