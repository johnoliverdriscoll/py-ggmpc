import argparse, base58, enum, json, sys
from functools import partial

class HelpFormatter(argparse.HelpFormatter):
  def add_argument(self, action):
    if action.help is not argparse.SUPPRESS:
      get_invocation = self._format_action_invocation
      invocations = [get_invocation(action)]
      current_indent = self._current_indent
      for subaction in self._iter_indented_subactions(action):
        indent_chg = self._current_indent - current_indent
        added_indent = 'x' * indent_chg
        invocations.append(added_indent+get_invocation(subaction))
      invocation_length = max([len(s) for s in invocations])
      action_length = invocation_length + self._current_indent
      self._action_max_length = max(self._action_max_length, action_length)
      self._add_item(self._format_action, [action])

def main():
  formatter = lambda prog: HelpFormatter(prog)

  parser = argparse.ArgumentParser(prog='ggmpc', formatter_class=formatter)

  subparsers = parser.add_subparsers(
    dest='COMMAND',
    metavar='COMMAND',
    required=True,
  )

  keyshare_parser = subparsers.add_parser(
    'keyshare',
    help='create key shares',
  )
  keyshare_parser.set_defaults(func=command_key_share)
  keyshare_parser.add_argument(
    '-i',
    type=int,
    help='player index',
    required=True,
  )
  keyshare_parser.add_argument(
    '-t',
    type=int,
    help='required threshold',
    required=True,
  )
  keyshare_parser.add_argument(
    '-n',
    type=int,
    help='number of players',
    required=True,
  )
  keyshare_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  keycombine_parser = subparsers.add_parser(
    'keycombine',
    help='combine key shares',
  )
  keycombine_parser.set_defaults(func=command_key_combine)
  keycombine_parser.add_argument(
    'KEYSHARE',
    type=str,
    help='your key share and shares received from other players',
    nargs='+',
  )
  keycombine_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signshare_parser = subparsers.add_parser(
    'signshare',
    help='create signing shares',
  )
  signshare_parser.set_defaults(func=command_sign_share)
  signshare_parser.add_argument(
    'KEYSHARE',
    type=str,
    help='combined key shares for all signing players',
    nargs='+',
  )
  signshare_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signconvert_parser = subparsers.add_parser(
    'signconvert',
    help='convert signing shares',
  )
  signconvert_parser.set_defaults(func=command_sign_convert)
  signconvert_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your signing share and shares received from other players',
    nargs='+',
  )
  signconvert_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signcombine_parser = subparsers.add_parser(
    'signcombine',
    help='combine converted signing shares and signature shares',
  )
  signcombine_parser.set_defaults(func=command_sign_combine)
  signcombine_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your signing shares and shares received from other players',
    nargs='+',
  )
  signcombine_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  sign_parser = subparsers.add_parser(
    'sign',
    help='sign message using converted signing shares',
  )
  sign_parser.set_defaults(func=command_sign)
  sign_parser.add_argument(
    'MESSAGE',
    type=str,
    help='message to sign',
    nargs=1,
  )
  sign_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your combined signing share',
    nargs='+',
  )
  sign_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  verify_parser = subparsers.add_parser(
    'verify',
    help='verify a signature',
  )
  verify_parser.set_defaults(func=command_verify)
  verify_parser.add_argument(
    'MESSAGE',
    type=str,
    help='message to verify',
    nargs=1,
  )
  verify_parser.add_argument(
    'SIGNATURE',
    type=str,
    help='signature to verify',
    nargs=1,
  )

  deserialize_parser = subparsers.add_parser(
    'deserialize',
    help='deserialize data',
  )
  deserialize_parser.set_defaults(func=command_deserialize)
  deserialize_parser.add_argument(
    'DATA',
    type=str,
    help='data to deserialize',
    nargs=1,
  )

  args = parser.parse_args()
  args.func(args)

def command_key_share(args):
  ser = partial(serialize, compress=args.compress)
  shares = ggmpc.key_share(args.i, args.t, args.n)
  P_i = shares[args.i]
  print('\nSave for yourself: %s' % ser(DataType.P_SHARE, P_i))
  for i in shares:
    if i != args.i:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.N_SHARE, shares[i]))
      )

def command_key_combine(args):
  ser = partial(serialize, compress=args.compress)
  shares = ggmpc.key_combine(list(map(deserialize, args.KEYSHARE)))
  P_i = shares[next(filter(lambda i: 'p' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.X_SHARE, P_i))
  for i in shares:
    if i != P_i['i']:
      print(
        '\nSave for player %d: %s' \
        % (i, ser(DataType.Y_SHARE, shares[i]))
      )

def command_sign_share(args):
  ser = partial(serialize, compress=args.compress)
  shares = ggmpc.sign_share(list(map(deserialize, args.KEYSHARE)))
  P_i = shares[next(filter(lambda i: 'p' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.W_SHARE, P_i))
  for i in shares:
    if i != P_i['i']:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.K_SHARE, shares[i]))
      )

def command_sign_convert(args):
  ser = partial(serialize, compress=args.compress)
  shares = list(map(deserialize, args.SIGNSHARE))
  for i in range(0, len(shares)):
    share = shares[i]
    if type(list(share.keys())[0]) == int:
      shares[i] = shares[i][next(filter(lambda i: 'p' in share[i], share))]
  shares = ggmpc.sign_convert(shares)
  P_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  P_j = shares[next(filter(lambda i: 'j' in shares[i], shares))]
  data_type = None
  if 'alpha' in P_i:
    data_type = DataType.G_SHARE
  else:
    data_type = DataType.B_SHARE
  print('\nSave for yourself:', ser(data_type, shares),)
  data_type = None
  if 'k' in P_j or 'alpha' in P_j:
    if 'k' in P_j:
      data_type = DataType.A_SHARE
    else:
      data_type = DataType.M_SHARE
    print('\nSend to player %d: %s' % (P_j['i'], ser(data_type, P_j)))

def command_sign_combine(args):
  ser = partial(serialize, compress=args.compress)
  shares = list(map(deserialize, args.SIGNSHARE))
  if 'r' in shares[0] and 's' in shares[0]:
    print('\n%s' % ser(DataType.SIGNATURE, ggmpc.sign_combine(shares)))
  else:
    shares = ggmpc.sign_combine(shares)
    P_i = shares[next(filter(lambda i: 'k' in shares[i], shares))]
    print('\nSave for yourself: %s' % ser(DataType.O_SHARE, P_i))
    for i in shares:
      if i != P_i['i']:
        print(
          '\nSend to player %d: %s' \
          % (i, ser(DataType.D_SHARE, shares[i]))
        )

def command_sign(args):
  ser = partial(serialize, compress=args.compress)
  M = args.MESSAGE[0].encode('ascii')
  shares = list(map(deserialize, args.SIGNSHARE))
  print('\n%s' % ser(DataType.S_SHARE, ggmpc.sign(M, shares)))

def command_verify(args):
  M = args.MESSAGE[0].encode('ascii')
  assert ggmpc.verify(M, deserialize(args.SIGNATURE[0]))
  print('\nverification succeeded')

def command_deserialize(args):
  print('\n%s' % json.dumps(encode(deserialize(args.DATA[0])), indent=2))

def encode(obj):
  encoded = {}
  for key in obj:
    val = obj[key]
    if type(val) == dict:
      encoded[key] = encode(val)
    elif key == 'i':
      encoded[key] = val
    elif key == 'j':
      encoded[key] = val
    elif key == 'y' or key == 'Gamma':
      encoded[key] = ggmpc.serialization.serialize_point(val).hex()
    else:
      length = (val.bit_length() + 7) // 8
      encoded[key] = ggmpc.serialization.serialize_int(val, length).hex()
  return encoded

def serialize_to_json(obj):
  return '\'' + json.dumps(encode(obj), separators=(',',':')) + '\''

def decode(encoded):
  obj = {}
  for key in encoded:
    val = encoded[key]
    if key.isnumeric():
      key = int(key)
    if type(val) == dict:
      obj[key] = decode(val)
    elif key == 'i':
      obj[key] = val
    elif key == 'j':
      obj[key] = val
    elif key == 'y' or key == 'Gamma':
      obj[key] = ggmpc.point_deserialize(bytes.fromhex(val))[1]
    else:
      obj[key] = ggmpc.deserialize_int(bytes.fromhex(val))[1]
  return obj

def deserialize_from_json(string):
  return decode(json.loads(string))

class DataType(enum.Enum):
  P_SHARE = 'pshare', 'i0x'
  N_SHARE = 'nshare', 'i0j1x'
  X_SHARE = 'xshare', 'i0x'
  Y_SHARE = 'yshare', 'i0j1x'
  W_SHARE = 'wshare', 'i0x'
  K_SHARE = 'kshare', 'i0j1x'
  B_SHARE = 'bshare', 'i0j1x'
  A_SHARE = 'ashare', 'i0j1x'
  M_SHARE = 'mshare', 'i0j1x'
  G_SHARE = 'gshare', 'i0j1x'
  O_SHARE = 'oshare', 'i0x'
  D_SHARE = 'dshare', 'i0j1x'
  S_SHARE = 'sshare', 'i0x'
  SIGNATURE = 'sigx',

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def serialize(data_type, data, compress=True):
  if compress:
    serialize = {
      DataType.P_SHARE: ggmpc.serialization.serialize_p_share,
      DataType.N_SHARE: ggmpc.serialization.serialize_n_share,
      DataType.X_SHARE: ggmpc.serialization.serialize_x_share,
      DataType.Y_SHARE: ggmpc.serialization.serialize_y_share,
      DataType.W_SHARE: ggmpc.serialization.serialize_w_share,
      DataType.K_SHARE: ggmpc.serialization.serialize_k_share,
      DataType.B_SHARE: ggmpc.serialization.serialize_b_share,
      DataType.A_SHARE: ggmpc.serialization.serialize_a_share,
      DataType.M_SHARE: ggmpc.serialization.serialize_m_share,
      DataType.G_SHARE: ggmpc.serialization.serialize_g_share,
      DataType.O_SHARE: ggmpc.serialization.serialize_o_share,
      DataType.D_SHARE: ggmpc.serialization.serialize_d_share,
      DataType.S_SHARE: ggmpc.serialization.serialize_s_share,
      DataType.SIGNATURE: ggmpc.serialization.serialize_signature,
    }
    data = serialize[data_type](data)
    i, j = None, None
    if len(data_type.value) > 1:
      if data_type.value[1].find('1') >= 0:
        j = data[1]
        data = data[:1] + data[2:]
      if data_type.value[1].find('0') >= 0:
        i = data[0]
        data = data[1:]
    prefix = data_type.value[0]
    if len(data_type.value) > 1:
      prefix += data_type.value[1]
      if i != None:
        index = len(data_type.value[0]) + data_type.value[1].find('0')
        prefix = prefix[:index] + alphabet[i - 1] + prefix[index + 1:]
      if j != None:
        index = len(data_type.value[0]) + data_type.value[1].find('1')
        prefix = prefix[:index] + alphabet[j - 1] + prefix[index + 1:]
    val = 0
    place = 1
    for c in prefix[::-1]:
      val += place * alphabet.index(c)
      place *= 58
    data += b'\x00\x00\x00\x00'
    val *= pow(58, len(base58.b58encode(data)))
    val += int.from_bytes(data, 'big')
    data = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    return base58.b58encode_check(data[:-4]).decode('ascii')
  return serialize_to_json(data)

def deserialize(data):
  if data[0] == '{':
    return deserialize_from_json(data)
  deserialize = {
    DataType.P_SHARE: ggmpc.serialization.deserialize_p_share,
    DataType.N_SHARE: ggmpc.serialization.deserialize_n_share,
    DataType.X_SHARE: ggmpc.serialization.deserialize_x_share,
    DataType.Y_SHARE: ggmpc.serialization.deserialize_y_share,
    DataType.W_SHARE: ggmpc.serialization.deserialize_w_share,
    DataType.K_SHARE: ggmpc.serialization.deserialize_k_share,
    DataType.B_SHARE: ggmpc.serialization.deserialize_b_share,
    DataType.A_SHARE: ggmpc.serialization.deserialize_a_share,
    DataType.M_SHARE: ggmpc.serialization.deserialize_m_share,
    DataType.G_SHARE: ggmpc.serialization.deserialize_g_share,
    DataType.O_SHARE: ggmpc.serialization.deserialize_o_share,
    DataType.D_SHARE: ggmpc.serialization.deserialize_d_share,
    DataType.S_SHARE: ggmpc.serialization.deserialize_s_share,
    DataType.SIGNATURE: ggmpc.serialization.deserialize_signature,
  }
  data_size = {
    DataType.P_SHARE: 450,
    DataType.N_SHARE: 451,
    DataType.X_SHARE: 450,
    DataType.Y_SHARE: 386,
    DataType.W_SHARE: 514,
    DataType.K_SHARE: 1154,
    DataType.B_SHARE: 3267,
    DataType.A_SHARE: 2690,
    DataType.M_SHARE: 1538,
    DataType.G_SHARE: 259,
    DataType.O_SHARE: 163,
    DataType.D_SHARE: 67,
    DataType.S_SHARE: 98,
    DataType.SIGNATURE: 97,
  }
  for data_type in DataType:
    if data[:len(data_type.value[0])] == data_type.value[0]:
      prefix_len = len(data_type.value[0])
      prefix = data[:prefix_len]
      i, j = None, None
      index_len = 0
      if len(data_type.value) > 1:
        prefix += data[prefix_len:prefix_len + len(data_type.value[1])]
        prefix_len += len(data_type.value[1])
        index = prefix[len(data_type.value[0]):]
        if data_type.value[1].find('0') >= 0:
          i = alphabet.index(index[data_type.value[1].find('0')]) + 1
          index_len += 1
        if data_type.value[1].find('1') >= 0:
          j = alphabet.index(index[data_type.value[1].find('1')]) + 1
          index_len += 1
      val = 0
      place = 1
      for c in prefix[::-1]:
        val += place * alphabet.index(c)
        place *= 58
      val *= pow(58, len(data) - prefix_len)
      data = base58.b58decode_check(data) + b'\x00\x00\x00\x00'
      data = int.from_bytes(data, 'big') - val
      data = data.to_bytes(data_size[data_type] - index_len + 4, 'big')
      if j != None:
        data = j.to_bytes(1, 'big') + data
      if i != None:
        data = i.to_bytes(1, 'big') + data
      rem, data = deserialize[data_type](data)
      assert rem == b'\x00\x00\x00\x00'
      return data

if __name__ == '__main__':
  main()
