import hashlib
import time
import sympy as sp
from fractions import Fraction
from math import comb

t = sp.Symbol('t', real=True, positive=True)

def sweep(ap):
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        s = 1 if diff > 0 else (-1 if diff < 0 else 0)
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

def normalize(calculation):
    poly = sp.expand(sp.simplify(calculation))
    all_exponents = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exponents)
    poly *= t**(-min_exp)
    poly = sp.expand(sp.simplify(poly))
    if poly.coeff(t, 0) < 0:
        poly *= -1
    return poly

def compute_poly(point):
    """Tính đa thức Alexander bằng evaluation-interpolation."""
    S = mine(point)
    n = len(S)
    R = [max(row) for row in S]
    min_S = [min(row) for row in S]
    D = sum(R[i] - min_S[i] for i in range(n))
    sum_R = sum(R)
    exp_mat = [[R[i] - S[i][j] for j in range(n)] for i in range(n)]

    eval_points = list(range(2, D + 3))
    eval_values = []
    for t_val in eval_points:
        mat = sp.Matrix([[t_val ** exp_mat[i][j] for j in range(n)] for i in range(n)])
        eval_values.append(int(mat.det()))

    xs = [Fraction(x) for x in eval_points]
    ys = [Fraction(y) for y in eval_values]
    dd = list(ys)
    n_pts = len(xs)
    for j in range(1, n_pts):
        for i in range(n_pts - 1, j - 1, -1):
            dd[i] = (dd[i] - dd[i-1]) / (xs[i] - xs[i-j])

    poly = [dd[n_pts - 1]]
    for i in range(n_pts - 2, -1, -1):
        new_poly = [Fraction(0)] * (len(poly) + 1)
        for k in range(len(poly)):
            new_poly[k + 1] += poly[k]
            new_poly[k] += (-xs[i]) * poly[k]
        new_poly[0] += dd[i]
        poly = new_poly

    int_coeffs = [int(c) for c in poly]

    divisor = [comb(n-1, k) * ((-1)**k) for k in range(n)]
    quotient = [0] * (len(int_coeffs) - len(divisor) + 1)
    remainder = list(int_coeffs)
    lead = divisor[-1]
    for i in range(len(quotient) - 1, -1, -1):
        quotient[i] = remainder[i + len(divisor) - 1] // lead
        for j in range(len(divisor)):
            remainder[i + j] -= quotient[i] * divisor[j]

    min_nonzero = next(k for k in range(len(quotient)) if quotient[k] != 0)
    shift = -(min_nonzero - sum_R)
    result = sum(quotient[k] * t**(k - sum_R + shift) for k in range(len(quotient)) if quotient[k] != 0)
    result = sp.expand(result)
    if result.coeff(t, 0) < 0:
        result = sp.expand(-result)
    return result

alice_pub = ([8,15,7,26,1,4,2,12,9,18,23,25,24,14,13,16,0,3,11,10,5,20,6,21,19,17,22],
             [5,2,23,3,25,9,26,8,24,7,14,18,12,4,20,21,6,1,19,22,10,0,16,17,15,11,13])
bob_pub = ([26,9,21,4,28,8,20,7,27,1,13,25,22,17,6,15,24,3,12,29,11,16,10,0,18,2,14,5,19,23],
           [5,18,28,27,25,19,23,13,21,24,16,15,8,29,14,11,26,22,9,7,10,3,2,6,0,12,17,20,1,4])
pub_info = ([11,0,2,4,8,3,1,10,7,6,9,5], [1,9,8,10,11,7,4,6,5,3,2,0])
ct_hex = "288cdf5ecf3eb860e2cb6790bff63baceaebb6ed511cd94dd0753bac59962ef0cd171231dc406ac3cdc2ff299d78390ff3"

poly_P = compute_poly(pub_info)
poly_A = compute_poly(alice_pub)
poly_B = compute_poly(bob_pub)

quotient, rem = (sp.Poly(poly_A, t) * sp.Poly(poly_B, t)).div(sp.Poly(poly_P, t))
assert rem.is_zero
shared_poly = normalize(quotient.as_expr())

shared_secret = hashlib.sha256(str(shared_poly).encode()).hexdigest()
ct = bytes.fromhex(ct_hex)
key = bytes.fromhex(shared_secret)
while len(key) < len(ct):
    key += hashlib.sha256(key).digest()
flag = bytes(a ^ b for a, b in zip(ct, key)).decode()
print(flag)