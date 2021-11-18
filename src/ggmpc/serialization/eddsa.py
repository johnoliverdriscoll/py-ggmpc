""" Serialization functions for EdDSA data. """

from .. import serialization

def serialize_u_share(share):
  """
  Serialize a u-share.

  :param share: U-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['y'], 32)
  ser += serialization.serialize_int(share['u'], 32)
  ser += serialization.serialize_int(share['prefix'], 32)
  return ser

def deserialize_u_share(ser):
  """
  Deserialize a u-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized u-share.

  :rtype: tuple
  """
  P_i = {}
  ser, P_i['i'] = serialization.deserialize_int(ser, 1)
  ser, P_i['y'] = serialization.deserialize_int(ser, 32)
  ser, P_i['u'] = serialization.deserialize_int(ser, 32)
  ser, P_i['prefix'] = serialization.deserialize_int(ser, 32)
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
  ser += serialization.serialize_int(share['y'], 32)
  ser += serialization.serialize_int(share['u'], 32)
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
  ser, P_j['y'] = serialization.deserialize_int(ser, 32)
  ser, P_j['u'] = serialization.deserialize_int(ser, 32)
  return ser, P_j

def serialize_p_share(P_i):
  """
  Serialize a p-share.

  :param share: P-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(P_i['i'], 1)
  ser += serialization.serialize_int(P_i['y'], 32)
  ser += serialization.serialize_int(P_i['x'], 32)
  ser += serialization.serialize_int(P_i['prefix'], 32)
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
  ser, P_i['y'] = serialization.deserialize_int(ser, 32)
  ser, P_i['x'] = serialization.deserialize_int(ser, 32)
  ser, P_i['prefix'] = serialization.deserialize_int(ser, 32)
  return ser, P_i

def serialize_j_share(P_j):
  """
  Serialize a j-share.

  :param share: J-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(P_j['i'], 1)
  ser += serialization.serialize_int(P_j['j'], 1)
  return ser

def deserialize_j_share(ser):
  """
  Deserialize a j-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized j-share.

  :rtype: tuple
  """
  P_j = {}
  ser, P_j['i'] = serialization.deserialize_int(ser, 1)
  ser, P_j['j'] = serialization.deserialize_int(ser, 1)
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
  ser += serialization.serialize_int(share['y'], 32)
  ser += serialization.serialize_int(share['x'], 32)
  ser += serialization.serialize_int(share['r'], 32)
  ser += serialization.serialize_int(share['R'], 32)
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
  ser, P_i['y'] = serialization.deserialize_int(ser, 32)
  ser, P_i['x'] = serialization.deserialize_int(ser, 32)
  ser, P_i['r'] = serialization.deserialize_int(ser, 32)
  ser, P_i['R'] = serialization.deserialize_int(ser, 32)
  return ser, P_i

def serialize_r_share(share):
  """
  Serialize an r-share.

  :param share: R-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['j'], 1)
  ser += serialization.serialize_int(share['r'], 32)
  ser += serialization.serialize_int(share['R'], 32)
  return ser

def deserialize_r_share(ser):
  """
  Deserialize an r-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized r-share.

  :rtype: tuple
  """
  P_j = {}
  ser, P_j['i'] = serialization.deserialize_int(ser, 1)
  ser, P_j['j'] = serialization.deserialize_int(ser, 1)
  ser, P_j['r'] = serialization.deserialize_int(ser, 32)
  ser, P_j['R'] = serialization.deserialize_int(ser, 32)
  return ser, P_j

def serialize_g_share(share):
  """
  Serialize a g-share.

  :param share: G-share to serialize.

  :type share: dict

  :return: Serialization of `share`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(share['i'], 1)
  ser += serialization.serialize_int(share['y'], 32)
  ser += serialization.serialize_int(share['gamma'], 32)
  ser += serialization.serialize_int(share['R'], 32)
  return ser

def deserialize_g_share(ser):
  """
  Deserialize a g-share.

  :param ser: Serialized data.

  :type ser: bytes

  :return: The remainder of the serialized data and the deserialized g-share.

  :rtype: tuple
  """
  P_i = {}
  ser, P_i['i'] = serialization.deserialize_int(ser, 1)
  ser, P_i['y'] = serialization.deserialize_int(ser, 32)
  ser, P_i['gamma'] = serialization.deserialize_int(ser, 32)
  ser, P_i['R'] = serialization.deserialize_int(ser, 32)
  return ser, P_i

def serialize_signature(signature):
  """
  Serialize a signature.

  :param share: Signature to serialize.

  :type share: dict

  :return: Serialization of `signature`.

  :rtype: bytes
  """
  ser = b''
  ser += serialization.serialize_int(signature['y'], 32)
  ser += serialization.serialize_int(signature['R'], 32)
  ser += serialization.serialize_int(signature['sigma'], 32)
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
  ser, sig['y'] = serialization.deserialize_int(ser, 32)
  ser, sig['R'] = serialization.deserialize_int(ser, 32)
  ser, sig['sigma'] = serialization.deserialize_int(ser, 32)
  return ser, sig
