import unittest
import src.ggmpc as ggmpc

class LibraryMethods(unittest.TestCase):

  def test_2_in_2_of_3(self):
    A = ggmpc.key_share(1, 2, 3)
    B = ggmpc.key_share(2, 2, 3)
    C = ggmpc.key_share(3, 2, 3)

    A, B, C = \
      ggmpc.key_combine((A[1], B[1], C[1])), \
      ggmpc.key_combine((A[2], B[2], C[2])), \
      ggmpc.key_combine((A[3], B[3], C[3])),

    AB = ggmpc.sign_share((A[1], A[2]))
    BA = ggmpc.sign_convert((B[1], B[2], AB[2]))
    AB = ggmpc.sign_convert((AB[1], BA[1]))
    BA = ggmpc.sign_convert((BA[2], AB[2]))

    AB, BA = ggmpc.sign_combine((AB,)), ggmpc.sign_combine((BA,))

    M = b'MPC on a Friday night'

    A, B = ggmpc.sign(M, (AB[1], BA[1])), ggmpc.sign(M, (AB[2], BA[2])),

    sig = ggmpc.sign_combine((A, B))

    assert ggmpc.verify(M, sig)

  def test_2_in_3_of_5(self):
    A = ggmpc.key_share(1, 3, 5)
    B = ggmpc.key_share(2, 3, 5)
    C = ggmpc.key_share(3, 3, 5)
    D = ggmpc.key_share(4, 3, 5)
    E = ggmpc.key_share(5, 3, 5)

    A, B, C, D, E = \
      ggmpc.key_combine((A[1], B[1], C[1], D[1], E[1])), \
      ggmpc.key_combine((A[2], B[2], C[2], D[2], E[2])), \
      ggmpc.key_combine((A[3], B[3], C[3], D[3], E[3])), \
      ggmpc.key_combine((A[4], B[4], C[4], D[4], E[4])), \
      ggmpc.key_combine((A[5], B[5], C[4], D[4], E[4])),

    AC = ggmpc.sign_share((A[1], A[2], A[3]))
    CA = ggmpc.sign_convert((C[1], C[2], C[3], AC[3]))
    AC = ggmpc.sign_convert((AC[1], CA[1]))
    CA = ggmpc.sign_convert((CA[3], AC[3]))

    AC, CA = ggmpc.sign_combine((AC,)), ggmpc.sign_combine((CA,))

    M = b'MPC on a Friday night'

    A, C = ggmpc.sign(M, (AC[1], CA[1])), ggmpc.sign(M, (AC[3], CA[3]))

    sig = ggmpc.sign_combine((A, C))

    assert not ggmpc.verify(M, sig)

  def test_3_in_3_of_5(self):
    A = ggmpc.key_share(1, 3, 5)
    B = ggmpc.key_share(2, 3, 5)
    C = ggmpc.key_share(3, 3, 5)
    D = ggmpc.key_share(4, 3, 5)
    E = ggmpc.key_share(5, 3, 5)

    A, B, C, D, E = \
      ggmpc.key_combine((A[1], B[1], C[1], D[1], E[1])), \
      ggmpc.key_combine((A[2], B[2], C[2], D[2], E[2])), \
      ggmpc.key_combine((A[3], B[3], C[3], D[3], E[3])), \
      ggmpc.key_combine((A[4], B[4], C[4], D[4], E[4])), \
      ggmpc.key_combine((A[5], B[5], C[4], D[4], E[4])),

    A = ggmpc.sign_share((A[1], A[2], A[3]))
    B = ggmpc.sign_share((B[1], B[2], B[3]))
    C = ggmpc.sign_share((C[1], C[2], C[3]))

    AB = ggmpc.sign_convert((A[1], B[1]))
    BA = ggmpc.sign_convert((B[2], AB[2]))
    AB = ggmpc.sign_convert((AB[1], BA[1]))

    AC = ggmpc.sign_convert((A[1], C[1]))
    CA = ggmpc.sign_convert((C[3], AC[3]))
    AC = ggmpc.sign_convert((AC[1], CA[1]))

    BC = ggmpc.sign_convert((B[2], C[2]))
    CB = ggmpc.sign_convert((C[3], BC[3]))
    BC = ggmpc.sign_convert((BC[2], CB[2]))

    ABC, BAC, CAB = \
      ggmpc.sign_combine((AB, AC)), \
      ggmpc.sign_combine((BA, BC)), \
      ggmpc.sign_combine((CA, CB)),

    M = b'MPC on a Friday night'

    A, B, C = \
      ggmpc.sign(M, (ABC[1], BAC[1], CAB[1])), \
      ggmpc.sign(M, (ABC[2], BAC[2], CAB[2])), \
      ggmpc.sign(M, (ABC[3], BAC[3], CAB[3])),


    sig = ggmpc.sign_combine((A, B, C))

    assert ggmpc.verify(M, sig)
