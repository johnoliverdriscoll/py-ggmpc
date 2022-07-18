import nacl, unittest
import src.ggmpc as ggmpc
import src.ggmpc.curves as curves

class Eddsa(unittest.TestCase):

  def test_2_in_2_of_3(self):
    mpc = ggmpc.Eddsa(curves.ed25519)

    A = mpc.key_share(1, 2, 3)
    B = mpc.key_share(2, 2, 3)
    C = mpc.key_share(3, 2, 3)

    A, B, C = \
      mpc.key_combine((A[1], B[1], C[1])), \
      mpc.key_combine((A[2], B[2], C[2])), \
      mpc.key_combine((A[3], B[3], C[3]))

    M = b'MPC on a Friday night'

    A, B = mpc.sign_share(M, (A[1], A[2])), mpc.sign_share(M, (B[1], B[2]))

    A, B = mpc.sign(M, (A[1], B[1])), mpc.sign(M, (A[2], B[2]))

    sig = mpc.sign_combine((A, B))

    assert mpc.verify(M, sig)

  def test_2_in_3_of_5(self):
    mpc = ggmpc.Eddsa(curves.ed25519)

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
      mpc.key_combine((A[5], B[5], C[5], D[5], E[5]))

    M = b'MPC on a Friday night'

    A, B = mpc.sign_share(M, (A[1], A[2])), mpc.sign_share(M, (B[1], B[2]))

    A, B = mpc.sign(M, (A[1], B[1])), mpc.sign(M, (A[2], B[2]))

    sig = mpc.sign_combine((A, B))

    try:
      assert not mpc.verify(M, sig)
    except nacl.exceptions.BadSignatureError:
      pass

  def test_3_in_3_of_5(self):
    mpc = ggmpc.Eddsa(curves.ed25519)

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
      mpc.key_combine((A[5], B[5], C[5], D[5], E[5]))

    M = b'MPC on a Friday night'

    A, B, C = \
      mpc.sign_share(M, (A[1], A[2], A[3])), \
      mpc.sign_share(M, (B[1], B[2], B[3])), \
      mpc.sign_share(M, (C[1], C[2], C[3]))

    A, B, C = \
      mpc.sign(M, (A[1], B[1], C[1])), \
      mpc.sign(M, (A[2], B[2], C[2])), \
      mpc.sign(M, (A[3], B[3], C[3]))

    sig = mpc.sign_combine((A, B, C))

    assert mpc.verify(M, sig)

  def test_offset(self):
    mpc = ggmpc.Eddsa(curves.ed25519)

    sk = mpc.secret_generate()

    A1 = mpc.key_share(1, 2, 3, sk)
    B1 = mpc.key_share(2, 2, 3)
    C1 = mpc.key_share(3, 2, 3)

    A2, B2, C2 = \
      mpc.key_combine((A1[1], B1[1], C1[1])), \
      mpc.key_combine((A1[2], B1[2], C1[2])), \
      mpc.key_combine((A1[3], B1[3], C1[3]))

    M = b'MPC on a Friday night'

    A3, B3 = mpc.sign_share(M, (A2[1], A2[2])), mpc.sign_share(M, (B2[1], B2[2]))

    A4, B4 = mpc.sign(M, (A3[1], B3[1])), mpc.sign(M, (A3[2], B3[2]))

    sig = mpc.sign_combine((A4, B4))
    assert mpc.verify(M, sig)

    pub = A2[1]['y']
    u = mpc.curve.scalar_random()
    y = mpc.curve.point_add(A1[1]['y'], mpc.curve.scalar_mul_base(u))
    shares = ggmpc.shamir.split(mpc.curve, mpc.curve.scalar_add(sk['u'], u), 2, 3)
    v = shares['v'][1:]
    del shares['v']
    A1[1]['v'], A1[2]['v'], A1[3]['v'] = v, v, v
    A1[1]['y'], A1[2]['y'], A1[3]['y'] = y, y, y
    A1[1]['u'], A1[2]['u'], A1[3]['u'] = shares.values()

    A2, B2, C2 = \
      mpc.key_combine((A1[1], B1[1], C1[1])), \
      mpc.key_combine((A1[2], B1[2], C1[2])), \
      mpc.key_combine((A1[3], B1[3], C1[3]))

    assert(A2[1]['y'] == mpc.curve.point_add(pub, mpc.curve.scalar_mul_base(u)))

    A3, B3 = mpc.sign_share(M, (A2[1], A2[2])), mpc.sign_share(M, (B2[1], B2[2]))

    A4, B4 = mpc.sign(M, (A3[1], B3[1])), mpc.sign(M, (A3[2], B3[2]))

    sig = mpc.sign_combine((A4, B4))
    assert mpc.verify(M, sig)
