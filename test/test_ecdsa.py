import ecdsa, unittest
import src.ggmpc as ggmpc
import src.ggmpc.curves as curves

class Ecdsa(unittest.TestCase):

  def test_2_in_2_of_3(self):
    mpc = ggmpc.Ecdsa(curves.secp256k1)

    A = mpc.key_share(1, 2, 3)
    B = mpc.key_share(2, 2, 3)
    C = mpc.key_share(3, 2, 3)

    A, B, C = \
      mpc.key_combine((A[1], B[1], C[1])), \
      mpc.key_combine((A[2], B[2], C[2])), \
      mpc.key_combine((A[3], B[3], C[3])),

    AB = mpc.sign_share((A[1], A[2]))
    BA = mpc.sign_convert((B[1], B[2], AB[2]))
    AB = mpc.sign_convert((AB[1], BA[1]))
    BA = mpc.sign_convert((BA[2], AB[2]))

    AB, BA = mpc.sign_combine((AB,)), mpc.sign_combine((BA,))

    M = b'MPC on a Friday night'

    A, B = mpc.sign(M, (AB[1], BA[1])), mpc.sign(M, (AB[2], BA[2])),

    sig = mpc.sign_combine((A, B))

    assert mpc.verify(M, sig)

  def test_2_in_3_of_5(self):
    mpc = ggmpc.Ecdsa(curves.secp256k1)
    
    A = mpc.key_share(1, 3, 5)
    B = mpc.key_share(2, 3, 5)
    C = mpc.key_share(3, 3, 5)
    D = mpc.key_share(4, 3, 5)
    E = mpc.key_share(5, 3, 5)

    A, B, C, D, E = \
      mpc.key_combine((A[1], B[1], C[1], D[1], E[1])), \
      mpc.key_combine((A[2], B[2], C[2], D[2], E[2])), \
      mpc.key_combine((A[3], B[3], C[3], D[3], E[3])), \
      mpc.key_combine((A[4], B[4], C[4], D[4], E[4])), \
      mpc.key_combine((A[5], B[5], C[4], D[4], E[4])),

    AC = mpc.sign_share((A[1], A[2], A[3]))
    CA = mpc.sign_convert((C[1], C[2], C[3], AC[3]))
    AC = mpc.sign_convert((AC[1], CA[1]))
    CA = mpc.sign_convert((CA[3], AC[3]))

    AC, CA = mpc.sign_combine((AC,)), mpc.sign_combine((CA,))

    M = b'MPC on a Friday night'

    A, C = mpc.sign(M, (AC[1], CA[1])), mpc.sign(M, (AC[3], CA[3]))

    sig = mpc.sign_combine((A, C))

    try:
      assert not mpc.verify(M, sig)
    except ecdsa.keys.BadSignatureError:
      pass

  def test_3_in_3_of_5(self):
    mpc = ggmpc.Ecdsa(curves.secp256k1)
    
    A = mpc.key_share(1, 3, 5)
    B = mpc.key_share(2, 3, 5)
    C = mpc.key_share(3, 3, 5)
    D = mpc.key_share(4, 3, 5)
    E = mpc.key_share(5, 3, 5)

    A, B, C, D, E = \
      mpc.key_combine((A[1], B[1], C[1], D[1], E[1])), \
      mpc.key_combine((A[2], B[2], C[2], D[2], E[2])), \
      mpc.key_combine((A[3], B[3], C[3], D[3], E[3])), \
      mpc.key_combine((A[4], B[4], C[4], D[4], E[4])), \
      mpc.key_combine((A[5], B[5], C[4], D[4], E[4])),

    A = mpc.sign_share((A[1], A[2], A[3]))
    B = mpc.sign_share((B[1], B[2], B[3]))
    C = mpc.sign_share((C[1], C[2], C[3]))

    AB = mpc.sign_convert((A[1], B[1]))
    BA = mpc.sign_convert((B[2], AB[2]))
    AB = mpc.sign_convert((AB[1], BA[1]))

    AC = mpc.sign_convert((A[1], C[1]))
    CA = mpc.sign_convert((C[3], AC[3]))
    AC = mpc.sign_convert((AC[1], CA[1]))

    BC = mpc.sign_convert((B[2], C[2]))
    CB = mpc.sign_convert((C[3], BC[3]))
    BC = mpc.sign_convert((BC[2], CB[2]))

    ABC, BAC, CAB = \
      mpc.sign_combine((AB, AC)), \
      mpc.sign_combine((BA, BC)), \
      mpc.sign_combine((CA, CB)),

    M = b'MPC on a Friday night'

    A, B, C = \
      mpc.sign(M, (ABC[1], BAC[1], CAB[1])), \
      mpc.sign(M, (ABC[2], BAC[2], CAB[2])), \
      mpc.sign(M, (ABC[3], BAC[3], CAB[3])),


    sig = mpc.sign_combine((A, B, C))

    assert mpc.verify(M, sig)
