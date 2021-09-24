import unittest, re, subprocess, sys
from functools import partial

def extract_results(stdout):
  r = re.compile('^([^:]+: )?([^\s]+)')
  return list(
    map(
      lambda chunk: r.match(chunk).group(2),
      filter(
        lambda line: len(line) > 0,
        stdout.decode('ascii').split('\n')
      )
    )
  )

def ggmpc(*args, **kwargs):
  process = subprocess.run(
    [sys.executable, '-m', 'src.ggmpc'] + list(args),
    capture_output=True,
  )
  if process.returncode != 0:
    raise RuntimeError(process.stderr.decode('ascii'))
  if len(process.stderr):
    sys.stderr.write(process.stderr.decode('ascii'))
  if not 'extract_results' in kwargs or kwargs['extract_results'] is True:
    return extract_results(process.stdout)

class Ecdsa(unittest.TestCase):

  ggmpc = partial(ggmpc, 'ecdsa')

  def test_2_in_2_of_3(self):
    A = Ecdsa.ggmpc('keyshare', '-i', '1', '-t', '2', '-n', '3')
    B = Ecdsa.ggmpc('keyshare', '-i', '2', '-t', '2', '-n', '3')
    C = Ecdsa.ggmpc('keyshare', '-i', '3', '-t', '2', '-n', '3')

    A, B, C = \
      Ecdsa.ggmpc('keycombine', A[0], B[1], C[1]), \
      Ecdsa.ggmpc('keycombine', A[1], B[0], C[2]), \
      Ecdsa.ggmpc('keycombine', A[2], B[2], C[0]),

    AB = Ecdsa.ggmpc('signshare', A[0], A[1])
    BA = Ecdsa.ggmpc('signconvert', B[0], B[1], AB[1])
    AB = Ecdsa.ggmpc('signconvert', AB[0], BA[1])
    BA = Ecdsa.ggmpc('signconvert', BA[0], AB[1])

    AB, BA = \
      Ecdsa.ggmpc('signcombine', AB[0]), \
      Ecdsa.ggmpc('signcombine', BA[0]),

    M = 'TOO MANY SECRETS'

    (A,), (B,) = \
      Ecdsa.ggmpc('sign', M, AB[0], BA[1]), \
      Ecdsa.ggmpc('sign', M, AB[1], BA[0]),

    sig, = Ecdsa.ggmpc('signcombine', A, B)

    Ecdsa.ggmpc('verify', M, sig, extract_results=False)

  def test_3_in_3_of_5(self):
    A = Ecdsa.ggmpc('keyshare', '-i', '1', '-t', '3', '-n', '5')
    B = Ecdsa.ggmpc('keyshare', '-i', '2', '-t', '3', '-n', '5')
    C = Ecdsa.ggmpc('keyshare', '-i', '3', '-t', '3', '-n', '5')
    D = Ecdsa.ggmpc('keyshare', '-i', '4', '-t', '3', '-n', '5')
    E = Ecdsa.ggmpc('keyshare', '-i', '5', '-t', '3', '-n', '5')

    A, B, C, D, E = \
      Ecdsa.ggmpc('keycombine', A[0], B[1], C[1], D[1], E[1]), \
      Ecdsa.ggmpc('keycombine', A[1], B[0], C[2], D[2], E[2]), \
      Ecdsa.ggmpc('keycombine', A[2], B[2], C[0], D[3], E[3]), \
      Ecdsa.ggmpc('keycombine', A[3], B[3], C[3], D[0], E[4]), \
      Ecdsa.ggmpc('keycombine', A[4], B[4], C[4], D[4], E[0]),

    A, B, C = \
      Ecdsa.ggmpc('signshare', A[0], A[1], A[2]), \
      Ecdsa.ggmpc('signshare', B[1], B[0], B[2]), \
      Ecdsa.ggmpc('signshare', C[1], C[2], C[0]),

    AB = Ecdsa.ggmpc('signconvert', A[0], B[1])
    BA = Ecdsa.ggmpc('signconvert', B[0], AB[1])
    AB = Ecdsa.ggmpc('signconvert', AB[0], BA[1])

    AC = Ecdsa.ggmpc('signconvert', A[0], C[1])
    CA = Ecdsa.ggmpc('signconvert', C[0], AC[1])
    AC = Ecdsa.ggmpc('signconvert', AC[0], CA[1])

    BC = Ecdsa.ggmpc('signconvert', B[0], C[2])
    CB = Ecdsa.ggmpc('signconvert', C[0], BC[1])
    BC = Ecdsa.ggmpc('signconvert', BC[0], CB[1])

    ABC, BAC, CAB = \
      Ecdsa.ggmpc('signcombine', AB[0], AC[0]), \
      Ecdsa.ggmpc('signcombine', BA[0], BC[0]), \
      Ecdsa.ggmpc('signcombine', CA[0], CB[0]),

    M = 'TOO MANY SECRETS'

    (A,), (B,), (C,) = \
      Ecdsa.ggmpc('sign', M, ABC[0], BAC[1], CAB[1]), \
      Ecdsa.ggmpc('sign', M, ABC[1], BAC[0], CAB[2]), \
      Ecdsa.ggmpc('sign', M, ABC[2], BAC[2], CAB[0]),

    sig, = Ecdsa.ggmpc('signcombine', A, B, C)

    Ecdsa.ggmpc('verify', M, sig, extract_results=False)

class Eddsa(unittest.TestCase):

  ggmpc = partial(ggmpc, 'eddsa')

  def test_2_in_2_of_3(self):
    A = Eddsa.ggmpc('keyshare', '-i', '1', '-t', '2', '-n', '3')
    B = Eddsa.ggmpc('keyshare', '-i', '2', '-t', '2', '-n', '3')
    C = Eddsa.ggmpc('keyshare', '-i', '3', '-t', '2', '-n', '3')

    A, B, C = \
      Eddsa.ggmpc('keycombine', A[0], B[1], C[1]), \
      Eddsa.ggmpc('keycombine', A[1], B[0], C[2]), \
      Eddsa.ggmpc('keycombine', A[2], B[2], C[0]),

    M = 'TOO MANY SECRETS'

    A, B = \
      Eddsa.ggmpc('signshare', M, A[0], A[1]), \
      Eddsa.ggmpc('signshare', M, B[0], B[1])

    (A,), (B,) = \
      Eddsa.ggmpc('sign', M, A[0], B[1]), \
      Eddsa.ggmpc('sign', M, A[1], B[0])

    sig, = Eddsa.ggmpc('signcombine', A, B)

    assert Eddsa.ggmpc('verify', M, sig)

  def test_3_in_3_of_5(self):
    A = Eddsa.ggmpc('keyshare', '-i', '1', '-t', '3', '-n', '5')
    B = Eddsa.ggmpc('keyshare', '-i', '2', '-t', '3', '-n', '5')
    C = Eddsa.ggmpc('keyshare', '-i', '3', '-t', '3', '-n', '5')
    D = Eddsa.ggmpc('keyshare', '-i', '4', '-t', '3', '-n', '5')
    E = Eddsa.ggmpc('keyshare', '-i', '5', '-t', '3', '-n', '5')

    A, B, C, D, E = \
      Eddsa.ggmpc('keycombine', A[0], B[1], C[1], D[1], E[1]), \
      Eddsa.ggmpc('keycombine', A[1], B[0], C[2], D[2], E[2]), \
      Eddsa.ggmpc('keycombine', A[2], B[2], C[0], D[3], E[3]), \
      Eddsa.ggmpc('keycombine', A[3], B[3], C[3], D[0], E[4]), \
      Eddsa.ggmpc('keycombine', A[4], B[4], C[4], D[4], E[0])

    M = 'TOO MANY SECRETS'

    A, B, C = \
      Eddsa.ggmpc('signshare', M, A[0], A[1], A[2]), \
      Eddsa.ggmpc('signshare', M, B[0], B[1], B[2]), \
      Eddsa.ggmpc('signshare', M, C[0], C[1], C[2])

    (A,), (B,), (C,) = \
      Eddsa.ggmpc('sign', M, A[0], B[1], C[1]), \
      Eddsa.ggmpc('sign', M, A[1], B[0], C[2]), \
      Eddsa.ggmpc('sign', M, A[2], B[2], C[0])

    sig, = Eddsa.ggmpc('signcombine', A, B, C)

    assert Eddsa.ggmpc('verify', M, sig)
