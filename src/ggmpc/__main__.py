import argparse, base58, enum, json
from functools import partial

from . import Ecdsa, Eddsa, curves, serialization

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

  command_subparsers = parser.add_subparsers(
    dest='COMMAND',
    required=True,
  )

  ecdsa_parser = command_subparsers.add_parser(
    'ecdsa',
    help='ECDSA commands',
  )
  ecdsa_parser.add_argument(
    '-c',
    help='specify curve',
    choices=['secp256k1'],
    default='secp256k1',
  )

  eddsa_parser = command_subparsers.add_parser(
    'eddsa',
    help='EdDSA commands',
  )
  eddsa_parser.add_argument(
    '-c',
    help='specify curve',
    choices=['ed25519'],
    default='ed25519',
  )

  # ECDSA subcommands.

  ecdsa_subparsers = ecdsa_parser.add_subparsers(
    dest='SUBCOMMAND',
    metavar='SUBCOMMAND',
    required=True,
  )

  keyshare_parser = ecdsa_subparsers.add_parser(
    'keyshare',
    help='create key shares',
  )
  keyshare_parser.set_defaults(func=ecdsa_key_share)
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

  keycombine_parser = ecdsa_subparsers.add_parser(
    'keycombine',
    help='combine key shares',
  )
  keycombine_parser.set_defaults(func=ecdsa_key_combine)
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

  signchallenge_parser = ecdsa_subparsers.add_parser(
    'signchallenge',
    help='create signing challenge',
  )
  signchallenge_parser.set_defaults(func=ecdsa_sign_challenge)
  signchallenge_parser.add_argument(
    'KEYSHARE',
    type=str,
    help='combined key shares for all signers',
    nargs='+',
  )
  signchallenge_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signshare_parser = ecdsa_subparsers.add_parser(
    'signshare',
    help='create signing shares',
  )
  signshare_parser.set_defaults(func=ecdsa_sign_share)
  signshare_parser.add_argument(
    'CHALLENGE',
    type=str,
    help='signing challenges for all signers',
    nargs='+',
  )
  signshare_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signconvert_parser = ecdsa_subparsers.add_parser(
    'signconvert',
    help='convert signing shares',
  )
  signconvert_parser.set_defaults(func=ecdsa_sign_convert)
  signconvert_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your signing share and shares received from other signers',
    nargs='+',
  )
  signconvert_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signcombine_parser = ecdsa_subparsers.add_parser(
    'signcombine',
    help='combine converted signing shares and signature shares',
  )
  signcombine_parser.set_defaults(func=ecdsa_sign_combine)
  signcombine_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your signing shares and shares received from other signers',
    nargs='+',
  )
  signcombine_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  sign_parser = ecdsa_subparsers.add_parser(
    'sign',
    help='sign message using converted signing shares',
  )
  sign_parser.set_defaults(func=ecdsa_sign)
  sign_parser.add_argument(
    'MESSAGE',
    type=str,
    help='message to sign',
    nargs=1,
  )
  sign_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your combined signing shares',
    nargs='+',
  )
  sign_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  verify_parser = ecdsa_subparsers.add_parser(
    'verify',
    help='verify a signature',
  )
  verify_parser.set_defaults(func=ecdsa_verify)
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

  # EdDSA subcommands.

  eddsa_subparsers = eddsa_parser.add_subparsers(
    dest='SUBCOMMAND',
    metavar='SUBCOMMAND',
    required=True,
  )

  secretgen_parser = eddsa_subparsers.add_parser(
    'secretgen',
    help='generate secret',
  )
  secretgen_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )
  secretgen_parser.set_defaults(func=eddsa_secret_generate)

  keyshare_parser = eddsa_subparsers.add_parser(
    'keyshare',
    help='create key shares',
  )
  keyshare_parser.set_defaults(func=eddsa_key_share)
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
    '-sk',
    type=str,
    help='optional secret returned from the secretgen command',
  )
  keyshare_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  keycombine_parser = eddsa_subparsers.add_parser(
    'keycombine',
    help='combine key shares',
  )
  keycombine_parser.set_defaults(func=eddsa_key_combine)
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

  signshare_parser = eddsa_subparsers.add_parser(
    'signshare',
    help='create signing shares',
  )
  signshare_parser.set_defaults(func=eddsa_sign_share)
  signshare_parser.add_argument(
    'MESSAGE',
    type=str,
    help='message to sign',
    nargs=1,
  )
  signshare_parser.add_argument(
    'KEYSHARE',
    type=str,
    help='key shares for all signers',
    nargs='+',
  )
  signshare_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  sign_parser = eddsa_subparsers.add_parser(
    'sign',
    help='sign message using signing shares',
  )
  sign_parser.set_defaults(func=eddsa_sign)
  sign_parser.add_argument(
    'MESSAGE',
    type=str,
    help='message to sign',
    nargs=1,
  )
  sign_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='signing shares',
    nargs='+',
  )
  sign_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  signcombine_parser = eddsa_subparsers.add_parser(
    'signcombine',
    help='combine signature shares',
  )
  signcombine_parser.set_defaults(func=eddsa_sign_combine)
  signcombine_parser.add_argument(
    'SIGNSHARE',
    type=str,
    help='your signing shares and shares received from other signers',
    nargs='+',
  )
  signcombine_parser.add_argument(
    '-nz',
    help='disable compression',
    dest='compress',
    action='store_false',
    default=True,
  )

  verify_parser = eddsa_subparsers.add_parser(
    'verify',
    help='verify a signature',
  )
  verify_parser.set_defaults(func=eddsa_verify)
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

  # Deserialize command

  deserialize_parser = command_subparsers.add_parser(
    'deserialize',
    help='deserialize data',
  )
  deserialize_parser.add_argument(
    'DATA',
    type=str,
    help='data to deserialize',
    nargs=1,
  )

  args = parser.parse_args()

  if args.COMMAND == 'ecdsa':
    args.func(Ecdsa(getattr(curves, args.c)), args)
  elif args.COMMAND == 'eddsa':
    args.func(Eddsa(getattr(curves, args.c)), args)
  elif args.COMMAND == 'deserialize':
    command_deserialize(args)
  
def ecdsa_key_share(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.key_share(args.i, args.t, args.n)
  P_i = shares[args.i]
  print('\nSave for yourself: %s' % ser(DataType.ECDSA_P_SHARE, P_i))
  for i in shares:
    if i != args.i:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.ECDSA_N_SHARE, shares[i]))
      )

def ecdsa_key_combine(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.key_combine(list(map(deserialize, args.KEYSHARE)))
  P_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.ECDSA_X_SHARE, P_i))
  for i in shares:
    if i != P_i['i']:
      print(
        '\nSave for player %d: %s' \
        % (i, ser(DataType.ECDSA_Y_SHARE, shares[i]))
      )

def ecdsa_sign_challenge(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.sign_challenge(list(map(deserialize, args.KEYSHARE)))
  S_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.ECDSA_H_SHARE, S_i))
  for i in shares:
    if i != S_i['i']:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.ECDSA_J_SHARE, shares[i]))
      )

def ecdsa_sign_share(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.sign_share(list(map(deserialize, args.CHALLENGE)))
  S_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.ECDSA_W_SHARE, S_i))
  for i in shares:
    if i != S_i['i']:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.ECDSA_K_SHARE, shares[i]))
      )

def ecdsa_sign_convert(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.sign_convert(list(map(deserialize, args.SIGNSHARE)))
  S_i, S_j = None, None
  for i in shares:
    if not 'j' in shares[i]:
      S_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
      S_j = shares[next(filter(lambda i: 'j' in shares[i], shares))]
      break
  if not S_i:
    S_i = shares[next(filter(lambda i: 'gamma' in shares[i], shares))]
    S_j = shares[next(filter(lambda i: not 'gamma' in shares[i], shares))]
  data_type = None
  if 'alpha' in S_i:
    data_type = DataType.ECDSA_G_SHARE
  else:
    data_type = DataType.ECDSA_B_SHARE
  print('\nSave for yourself:', ser(data_type, S_i))
  data_type = None
  if 'k' in S_j or 'alpha' in S_j:
    if 'k' in S_j:
      data_type = DataType.ECDSA_A_SHARE
    else:
      data_type = DataType.ECDSA_M_SHARE
    print('\nSend to player %d: %s' % (S_j['i'], ser(data_type, S_j)))

def ecdsa_sign_combine(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = list(map(deserialize, args.SIGNSHARE))
  if 'r' in shares[0] and 's' in shares[0]:
    print('\n%s' % ser(DataType.ECDSA_SIGNATURE, mpc.sign_combine(shares)))
  else:
    shares = mpc.sign_combine(shares)
    S_i = shares[next(filter(lambda i: 'k' in shares[i], shares))]
    print('\nSave for yourself: %s' % ser(DataType.ECDSA_O_SHARE, S_i))
    for i in shares:
      if i != S_i['i']:
        print(
          '\nSend to player %d: %s' \
          % (i, ser(DataType.ECDSA_D_SHARE, shares[i]))
        )

def ecdsa_sign(mpc, args):
  ser = partial(serialize, compress=args.compress)
  M = args.MESSAGE[0].encode('ascii')
  shares = list(map(deserialize, args.SIGNSHARE))
  print(
    '\nSend to all players: %s' \
    % ser(DataType.ECDSA_S_SHARE, mpc.sign(M, shares))
  )

def ecdsa_verify(mpc, args):
  M = args.MESSAGE[0].encode('ascii')
  assert mpc.verify(M, deserialize(args.SIGNATURE[0]))
  print('\nVerification succeeded')

def eddsa_secret_generate(mpc, args):
  ser = partial(serialize, compress=args.compress)
  sk = mpc.secret_generate()
  print('\nSave for yourself: %s' % ser(DataType.EDDSA_SECRET, sk))

def eddsa_key_share(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.key_share(args.i, args.t, args.n)
  P_i = shares[args.i]
  print('\nSave for yourself: %s' % ser(DataType.EDDSA_U_SHARE, P_i))
  for i in shares:
    if i != args.i:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.EDDSA_Y_SHARE, shares[i]))
      )

def eddsa_key_combine(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = mpc.key_combine(list(map(deserialize, args.KEYSHARE)))
  P_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.EDDSA_P_SHARE, P_i))
  for i in shares:
    if i != P_i['i']:
      print(
        '\nSave for player %d: %s' \
        % (i, ser(DataType.EDDSA_J_SHARE, shares[i]))
      )

def eddsa_sign_share(mpc, args):
  ser = partial(serialize, compress=args.compress)
  M = args.MESSAGE[0].encode('ascii')
  shares = mpc.sign_share(M, list(map(deserialize, args.KEYSHARE)))
  P_i = shares[next(filter(lambda i: not 'j' in shares[i], shares))]
  print('\nSave for yourself: %s' % ser(DataType.EDDSA_X_SHARE, P_i))
  for i in shares:
    if i != P_i['i']:
      print(
        '\nSend to player %d: %s' \
        % (i, ser(DataType.EDDSA_R_SHARE, shares[i]))
      )

def eddsa_sign(mpc, args):
  ser = partial(serialize, compress=args.compress)
  M = args.MESSAGE[0].encode('ascii')
  shares = list(map(deserialize, args.SIGNSHARE))
  print(
    '\nSend to all players: %s' \
    % ser(DataType.EDDSA_G_SHARE, mpc.sign(M, shares))
  )

def eddsa_sign_combine(mpc, args):
  ser = partial(serialize, compress=args.compress)
  shares = list(map(deserialize, args.SIGNSHARE))
  print(
    '\n%s' \
    % ser(DataType.EDDSA_SIGNATURE, mpc.sign_combine(shares))
  )

def eddsa_verify(mpc, args):
  M = args.MESSAGE[0].encode('ascii')
  assert mpc.verify(M, deserialize(args.SIGNATURE[0]))
  print('\nVerification succeeded')

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
      if type(val) == int:
        encoded[key] = serialization.serialize_int(val, 32).hex()
      else:
        encoded[key] = serialization.ecdsa.serialize_point(val).hex()
    else:
      length = (val.bit_length() + 7) // 8
      encoded[key] = serialization.serialize_int(val, length).hex()
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
      ser = bytes.fromhex(val)
      if len(ser) == 33:
        obj[key] = serialization.ecdsa.deserialize_point(ser)[1]
      else:
        obj[key] = serialization.deserialize_int(ser, 32)[1]
    else:
      ser = bytes.fromhex(val)
      obj[key] = serialization.deserialize_int(ser, len(ser))[1]
  return obj

def deserialize_from_json(string):
  return decode(json.loads(string))

class DataType(enum.Enum):
  ECDSA_P_SHARE = 'pshc', '_i0_'
  ECDSA_N_SHARE = 'nshc', '_i0j1_'
  ECDSA_X_SHARE = 'xshc', '_i0_'
  ECDSA_Y_SHARE = 'yshc', '_i0j1'
  ECDSA_H_SHARE = 'hshc', '_i0_'
  ECDSA_J_SHARE = 'jshc', '_i0j1_'
  ECDSA_W_SHARE = 'wshc', '_i0_'
  ECDSA_K_SHARE = 'kshc', '_i0j1_'
  ECDSA_B_SHARE = 'bshc', '_i0_'
  ECDSA_A_SHARE = 'ashc', '_i0j1_'
  ECDSA_G_SHARE = 'gshc', '_i0j1_'
  ECDSA_M_SHARE = 'mshc', '_i0j1_'
  ECDSA_O_SHARE = 'oshc', '_i0_'
  ECDSA_D_SHARE = 'dshc', '_i0j1_'
  ECDSA_S_SHARE = 'sshc', '_i0_'
  ECDSA_SIGNATURE = 'sigc_',
  EDDSA_SECRET = 'sk_',
  EDDSA_U_SHARE = 'ushd', '_i0_'
  EDDSA_Y_SHARE = 'yshd', '_i0j1_'
  EDDSA_P_SHARE = 'pshd', '_i0_'
  EDDSA_J_SHARE = 'jshd', '_i0j1'
  EDDSA_X_SHARE = 'xshd', '_i0_'
  EDDSA_R_SHARE = 'rshd', '_i0j1_'
  EDDSA_G_SHARE = 'gshd', '_i0_'
  EDDSA_SIGNATURE = 'sigd_',

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def serialize(data_type, data, compress=True):
  if compress:
    serialize = {
      DataType.ECDSA_P_SHARE: serialization.ecdsa.serialize_p_share,
      DataType.ECDSA_N_SHARE: serialization.ecdsa.serialize_n_share,
      DataType.ECDSA_X_SHARE: serialization.ecdsa.serialize_x_share,
      DataType.ECDSA_Y_SHARE: serialization.ecdsa.serialize_y_share,
      DataType.ECDSA_H_SHARE: serialization.ecdsa.serialize_h_share,
      DataType.ECDSA_J_SHARE: serialization.ecdsa.serialize_j_share,
      DataType.ECDSA_W_SHARE: serialization.ecdsa.serialize_w_share,
      DataType.ECDSA_K_SHARE: serialization.ecdsa.serialize_k_share,
      DataType.ECDSA_B_SHARE: serialization.ecdsa.serialize_b_share,
      DataType.ECDSA_A_SHARE: serialization.ecdsa.serialize_a_share,
      DataType.ECDSA_M_SHARE: serialization.ecdsa.serialize_m_share,
      DataType.ECDSA_G_SHARE: serialization.ecdsa.serialize_g_share,
      DataType.ECDSA_O_SHARE: serialization.ecdsa.serialize_o_share,
      DataType.ECDSA_D_SHARE: serialization.ecdsa.serialize_d_share,
      DataType.ECDSA_S_SHARE: serialization.ecdsa.serialize_s_share,
      DataType.ECDSA_SIGNATURE: serialization.ecdsa.serialize_signature,
      DataType.EDDSA_SECRET: serialization.eddsa.serialize_secret,
      DataType.EDDSA_U_SHARE: serialization.eddsa.serialize_u_share,
      DataType.EDDSA_Y_SHARE: serialization.eddsa.serialize_y_share,
      DataType.EDDSA_P_SHARE: serialization.eddsa.serialize_p_share,
      DataType.EDDSA_J_SHARE: serialization.eddsa.serialize_j_share,
      DataType.EDDSA_X_SHARE: serialization.eddsa.serialize_x_share,
      DataType.EDDSA_R_SHARE: serialization.eddsa.serialize_r_share,
      DataType.EDDSA_G_SHARE: serialization.eddsa.serialize_g_share,
      DataType.EDDSA_SIGNATURE: serialization.eddsa.serialize_signature,
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
    if len(data) > 0:
      return prefix + base58.b58encode_check(data).decode('ascii')
    return prefix
  return serialize_to_json(data)

def deserialize(data):
  if data[0] == '{':
    return deserialize_from_json(data)
  deserialize = {
    DataType.ECDSA_P_SHARE: serialization.ecdsa.deserialize_p_share,
    DataType.ECDSA_N_SHARE: serialization.ecdsa.deserialize_n_share,
    DataType.ECDSA_X_SHARE: serialization.ecdsa.deserialize_x_share,
    DataType.ECDSA_Y_SHARE: serialization.ecdsa.deserialize_y_share,
    DataType.ECDSA_H_SHARE: serialization.ecdsa.deserialize_h_share,
    DataType.ECDSA_J_SHARE: serialization.ecdsa.deserialize_j_share,
    DataType.ECDSA_W_SHARE: serialization.ecdsa.deserialize_w_share,
    DataType.ECDSA_K_SHARE: serialization.ecdsa.deserialize_k_share,
    DataType.ECDSA_B_SHARE: serialization.ecdsa.deserialize_b_share,
    DataType.ECDSA_A_SHARE: serialization.ecdsa.deserialize_a_share,
    DataType.ECDSA_M_SHARE: serialization.ecdsa.deserialize_m_share,
    DataType.ECDSA_G_SHARE: serialization.ecdsa.deserialize_g_share,
    DataType.ECDSA_O_SHARE: serialization.ecdsa.deserialize_o_share,
    DataType.ECDSA_D_SHARE: serialization.ecdsa.deserialize_d_share,
    DataType.ECDSA_S_SHARE: serialization.ecdsa.deserialize_s_share,
    DataType.ECDSA_SIGNATURE: serialization.ecdsa.deserialize_signature,
    DataType.EDDSA_SECRET: serialization.eddsa.deserialize_secret,
    DataType.EDDSA_U_SHARE: serialization.eddsa.deserialize_u_share,
    DataType.EDDSA_Y_SHARE: serialization.eddsa.deserialize_y_share,
    DataType.EDDSA_P_SHARE: serialization.eddsa.deserialize_p_share,
    DataType.EDDSA_J_SHARE: serialization.eddsa.deserialize_j_share,
    DataType.EDDSA_X_SHARE: serialization.eddsa.deserialize_x_share,
    DataType.EDDSA_R_SHARE: serialization.eddsa.deserialize_r_share,
    DataType.EDDSA_G_SHARE: serialization.eddsa.deserialize_g_share,
    DataType.EDDSA_SIGNATURE: serialization.eddsa.deserialize_signature,
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
        pos0 = data_type.value[1].find('0')
        pos1 = data_type.value[1].find('1')
        if pos0 >= 0:
          i = alphabet.index(index[pos0]) + 1
        if pos1 >= 0:
          j = alphabet.index(index[pos1]) + 1
      if len(data) > prefix_len:
        data = base58.b58decode_check(data[prefix_len:])
      else:
        data = b''
      if j != None:
        data = j.to_bytes(1, 'big') + data
      if i != None:
        data = i.to_bytes(1, 'big') + data
      rem, data = deserialize[data_type](data)
      assert len(rem) == 0
      return data

if __name__ == '__main__':
  main()
