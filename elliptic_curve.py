#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Tuple
from six import int2byte, b

def int_to_string(x):
    """Convert integer x into a string of bytes, as per X9.62."""
    assert x >= 0
    if x == 0:
        return b("\0")
    result = []
    while x:
        ordinal = x & 0xFF
        result.append(int2byte(ordinal))
        x >>= 8

    result.reverse()
    return b("").join(result)


def string_to_int(s):
    """Convert a string of bytes into an integer, as per X9.62."""
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = 256 * result + c
    return result


def modulo_inv(a: int, b: int) -> int:
    """基于扩展欧几里得算法求逆元a^{-1} mod b
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

    ax + by = gcd(a, b)
    when a and b are coprime, x is the modular multiplicative inverse of a modulo b

    Args:
        a (int): ax + by = gcd(a, b)
        b (int): ax + by = gcd(a, b)

    Returns:
        int: x (a^{-1})
    """
    if a == 0:
        return 0

    lm, hm = 1, 0
    low, high = a % b, b
    while low > 1:
        ratio = high // low # floor division operator in python3
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    del high # shut pylint up
    return lm % b


class EllipticCurve:
    def __init__(self,
                 p_curve: int,
                 a_curve: int,
                 b_curve: int,
                 point_generator_x: int,
                 point_generator_y: int,
                 n_curve: int):
        """[summary]

        Args:
            p_curve (int): [description]
            a_curve (int): [description]
            b_curve (int): [description]
            generator_point_x (int): [description]
            generator_point_y (int): [description]
            n_curve (int): [description]
        """
        self.p_curve = p_curve
        self.a_curve = a_curve
        self.b_curve = b_curve
        self.point_generator_x = point_generator_x
        self.point_generator_y = point_generator_y
        self.point_generator = (point_generator_x, point_generator_y)
        self.n_curve = n_curve
        
    def EC_add(self,
               point_P: Tuple[int, int],
               point_Q: Tuple[int, int]) -> Tuple[int, int]:
        """Adding two points P and Q on an elliptic curve (P != Q and P != -Q)
        Geometry approach:
        # https://www.certicom.com/content/certicom/en/21-elliptic-curve-addition-a-geometric-approach.html
        1. Draw a straight line between P and Q
        2. The line will intersect the curve at exactly on point -R
        3. The reflection of the point -R with respect to x-axis gives the point R,
           which is the result of addition of points P and Q
        
        Methamatical approach
        # https://www.certicom.com/content/certicom/en/22-elliptic-curve-addition-an-algebraic-approach.html
        1. lambda (the scope of the line) = (point_Q_y - point_P_y) * (point_Q_x - point_P_x)^{-1} (mod p)
        2. point_R_x = lambda * lambda - point_P_x - point_Q_x (mod p)
        3. point_R_y = lambda * (point_P_x - point_R_x) - point_P_y (mod p)
        
        Args:
            point_P (tuple[int, int]): [description]
            point_Q (tuple[int, int]): [description]

        Returns:
            tuple[int, int]: [description]
        """
        _lambda = ((point_Q[1]-point_P[1]) * 
                  modulo_inv(point_Q[0] - point_P[0], self.p_curve)) % self.p_curve
        x = (_lambda * _lambda - point_P[0] - point_Q[0]) % self.p_curve
        y = (_lambda * (point_P[0] - x) - point_P[1]) % self.p_curve
        return (x, y)

    def EC_double(self, point_P: Tuple[int, int]) -> Tuple[int, int]:
        """Point doubling of point P on an elliptic curve
        Geometry approach:
        # https://www.certicom.com/content/certicom/en/213-doubling-the-point-P.html
        1. Draw a tangent line to the elliptic curve at point P
        2. The line intersects the eliptic curve at the point -R
        3. The reflection of the point -R with respect to x-axis gives the point R,
           which is the result of doubling of points P
        
        Methamatical approach:
        # https://www.certicom.com/content/certicom/en/22-elliptic-curve-addition-an-algebraic-approach.html
        1. lambda (the scope of the line) = (3 * point_P_x * point_P_x + a_curve) * (2 * point_P_y)^{-1} (mod p) # 求导
        2. point_R_x = lambda * lambda - 2 * point_P_x (mod p)
        3. point_R_y = lambda * (point_P_x - point_R_x) - point_P_y (mod p)

        Args:
            point_P (tuple[int, int]): [description]

        Returns:
            tuple[int, int]: [description]
        """
        _lambda = ((3 * point_P[0]*point_P[0] + self.a_curve) *
                   modulo_inv((2*point_P[1]), self.p_curve)) % self.p_curve
        x = (_lambda*_lambda-2*point_P[0]) % self.p_curve
        y = (_lambda*(point_P[0]-x)-point_P[1]) % self.p_curve
        return (x, y)

    def EC_multiply(self,
                    point_P: Tuple[int, int],
                    scalar: int) -> Tuple[int, int]:
        """Elliptic curve point multiplication using double-and-add algorithm

        # https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
        Args:
            point_P (tuple[int, int]): [description]
            scalar (int): [description]

        Raises:
            Exception: [description]

        Returns:
            tuple[int, int]: [description]
        """
        if scalar == 0 or scalar >= self.n_curve:
            raise Exception("Invalid Scalar/Private Key")

        scalar_binary_str = str(bin(scalar))[2:]
        Q = point_P
        for i in range(1, len(scalar_binary_str)):
            Q = self.EC_double(Q)
            if scalar_binary_str[i] == "1":
                Q = self.EC_add(Q, point_P)
        return Q

    def ecdsa_sign(self, private_key: int, raw_int_to_sign: int, random_k: int) -> Tuple[int, int]:
        """Return a signature for the provided raw int, using the provided random nonce and private key.  
        Args:
            private_key (int): [description]
            raw_int_to_sign (int): [description]
            random_k (int): [description]

        Raises:
            RuntimeError: [description]
            Exception: [description]

        Returns:
            Tuple[int, int]: (r, s) pair
        """        
        G = self.point_generator
        n = self.n_curve
        k = random_k % n

        point_kG = self.EC_multiply(G, k)

        r = point_kG[0] % n
        while r == 0:
            point_kG = self.EC_multiply(G, k)
            r = point_kG[0] % n

        s = (modulo_inv(k, n) *((raw_int_to_sign + r * private_key) % n)) % n

        if s == 0:
            raise Exception("amazingly unlucky random number s")

        return (r, s)
