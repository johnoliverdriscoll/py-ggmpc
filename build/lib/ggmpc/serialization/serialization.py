""" Serialization functions. """

from . import ecdsa, eddsa

def serialize_int(x, length):
  """
  Serialize an integer as a big-endian byte array.

  :param x: The integer to serialize.

  :type x: int

  :param length: Byte length of serialized array.

  :type length: int

  :return: Serialized integer.

  :rtype: bytes
  """
  return x.to_bytes(length, 'big')


def deserialize_int(ser, length):
  """
  Deserialize an integer from a big-endian byte array.

  :param ser: Serialized data.

  :type ser: bytes

  :param length: Byte length of serialized integer.

  :type length: int

  :return: Deserialized integer.

  :rtype: int
  """
  x = int.from_bytes(ser[:length], 'big')
  return ser[length:], x
