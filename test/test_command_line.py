import unittest, re, subprocess, sys

class CommandLine(unittest.TestCase):

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
      [sys.executable, '-m', 'ggmpc'] + list(args),
      capture_output=True,
    )
    if process.returncode != 0:
      raise RuntimeError(process.stderr.decode('ascii'))
    if len(process.stderr):
      sys.stderr.write(process.stderr.decode('ascii'))
    if not 'extract_results' in kwargs or kwargs['extract_results'] is True:
      return CommandLine.extract_results(process.stdout)

  def test_2_in_2_of_3(self):
    A = CommandLine.ggmpc('keyshare', '-i', '1', '-t', '2', '-n', '3')
    B = CommandLine.ggmpc('keyshare', '-i', '2', '-t', '2', '-n', '3')
    C = CommandLine.ggmpc('keyshare', '-i', '3', '-t', '2', '-n', '3')

    A, B, C = \
      CommandLine.ggmpc('keycombine', A[0], B[1], C[1]), \
      CommandLine.ggmpc('keycombine', A[1], B[0], C[2]), \
      CommandLine.ggmpc('keycombine', A[2], B[2], C[0]),

    AB = CommandLine.ggmpc('signshare', A[0], A[1])
    BA = CommandLine.ggmpc('signconvert', B[0], B[1], AB[1])
    AB = CommandLine.ggmpc('signconvert', AB[0], BA[1])
    BA = CommandLine.ggmpc('signconvert', BA[0], AB[1])

    AB, BA = \
      CommandLine.ggmpc('signcombine', AB[0]), \
      CommandLine.ggmpc('signcombine', BA[0]),

    m = 'TOO MANY SECRETS'

    (A,), (B,) = \
      CommandLine.ggmpc('sign', m, AB[0], BA[1]), \
      CommandLine.ggmpc('sign', m, AB[1], BA[0]),

    sig, = CommandLine.ggmpc('signcombine', A, B)

    CommandLine.ggmpc('verify', m, sig, extract_results=False)

  def test_3_in_3_of_5(self):
    A = CommandLine.ggmpc('keyshare', '-i', '1', '-t', '3', '-n', '5')
    B = CommandLine.ggmpc('keyshare', '-i', '2', '-t', '3', '-n', '5')
    C = CommandLine.ggmpc('keyshare', '-i', '3', '-t', '3', '-n', '5')
    D = CommandLine.ggmpc('keyshare', '-i', '4', '-t', '3', '-n', '5')
    E = CommandLine.ggmpc('keyshare', '-i', '5', '-t', '3', '-n', '5')

    A, B, C, D, E = \
      CommandLine.ggmpc('keycombine', A[0], B[1], C[1], D[1], E[1]), \
      CommandLine.ggmpc('keycombine', A[1], B[0], C[2], D[2], E[2]), \
      CommandLine.ggmpc('keycombine', A[2], B[2], C[0], D[3], E[3]), \
      CommandLine.ggmpc('keycombine', A[3], B[3], C[3], D[0], E[4]), \
      CommandLine.ggmpc('keycombine', A[4], B[4], C[4], D[4], E[0]),

    A, B, C = \
      CommandLine.ggmpc('signshare', A[0], A[1], A[2]), \
      CommandLine.ggmpc('signshare', B[1], B[0], B[2]), \
      CommandLine.ggmpc('signshare', C[1], C[2], C[0]),

    AB = CommandLine.ggmpc('signconvert', A[0], B[1])
    BA = CommandLine.ggmpc('signconvert', B[0], AB[1])
    AB = CommandLine.ggmpc('signconvert', AB[0], BA[1])

    AC = CommandLine.ggmpc('signconvert', A[0], C[1])
    CA = CommandLine.ggmpc('signconvert', C[0], AC[1])
    AC = CommandLine.ggmpc('signconvert', AC[0], CA[1])

    BC = CommandLine.ggmpc('signconvert', B[0], C[2])
    CB = CommandLine.ggmpc('signconvert', C[0], BC[1])
    BC = CommandLine.ggmpc('signconvert', BC[0], CB[1])

    ABC, BAC, CAB = \
      CommandLine.ggmpc('signcombine', AB[0], AC[0]), \
      CommandLine.ggmpc('signcombine', BA[0], BC[0]), \
      CommandLine.ggmpc('signcombine', CA[0], CB[0]),

    m = 'TOO MANY SECRETS'

    (A,), (B,), (C,) = \
      CommandLine.ggmpc('sign', m, ABC[0], BAC[1], CAB[1]), \
      CommandLine.ggmpc('sign', m, ABC[1], BAC[0], CAB[2]), \
      CommandLine.ggmpc('sign', m, ABC[2], BAC[2], CAB[0]),

    sig, = CommandLine.ggmpc('signcombine', A, B, C)

    CommandLine.ggmpc('verify', m, sig, extract_results=False)
