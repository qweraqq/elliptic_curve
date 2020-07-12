#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
from elliptic_curve import (EllipticCurve,
                            modulo_inv,
                            string_to_int,
                            int_to_string)

def secp256k1_demo():
    # secp256k1 domain parameters
    # The proven prime
    Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 

    # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
    Acurve = 0                                                    
    Bcurve = 7

    # Generator point
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    point_generator = (int(Gx), int(Gy))

    # Number of points in the field (order of the field)
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 

    ec_curve = EllipticCurve(Pcurve, Acurve, Bcurve, Gx, Gy, N)
    # int("hex_string" ,16)

    # Replace with any private key (randomly generated)
    priv_key = 0x5712f72ca98165625fe652f1911e7e5795a86d56e724f7cd4bf3375c5fcc26b8
    print("The private key: 0x{:064x}".format(priv_key))
    print("The private key: {}".format(hex(priv_key)))
    print(f"The private key: 0x{priv_key:064x}")

    print("\r\n\r\n******* ECDLP Public Key Generation *********") 
    point_public_key = ec_curve.EC_multiply(point_generator, priv_key)
    print(f"The public key: (x = 0x{point_public_key[0]:064x}, y = {point_public_key[1]:064x})")

    print("\r\n\r\n*****ECDSA Vulnerability Demo*****")
    raw_int_1_to_sign = string_to_int("\xC8\xDB\x87>t\xC4\xC8\r\x1E\xF7c\xDC@]\xDB\xCF\xE8%\x89\xB1\xDE?\x87:C1\x02F?Xl|")
    raw_int_2_to_sign = string_to_int("\x9B$j^KA\xF2\xB32\xE0\xD3\n43|\xF4\xEFL\xDB\tV\xAF\xCB\xD6dB\x90}\xD9\x05\xC6\x0F")
    ecdsa_sign_1_r = 21505829891763648114329055987619236494102133314575206970830385799158076338148
    ecdsa_sign_2_r = 21505829891763648114329055987619236494102133314575206970830385799158076338148
    ecdsa_sign_1_s = 29982806498908468698285880421449377990633260409100070838917643476964059158422
    ecdsa_sign_2_s = 2688866553165465396487518855200337458372728620912733016156314344402296269120

    if ecdsa_sign_1_r == ecdsa_sign_2_r:
        print("Signature with same r -> VULNERABLE")

    # Use same r vulnerability to get private key
    k = ((raw_int_1_to_sign - raw_int_2_to_sign) % ec_curve.n_curve) * \
        modulo_inv(ecdsa_sign_1_s - ecdsa_sign_2_s, ec_curve.n_curve)
    k = k % ec_curve.n_curve

    cracked_priv_key = (((((ecdsa_sign_1_s * k) % ec_curve.n_curve)
                        - raw_int_1_to_sign) % ec_curve.n_curve) *
                        modulo_inv(ecdsa_sign_1_r, ec_curve.n_curve)) % ec_curve.n_curve

    print(f"The cracked private key: 0x{cracked_priv_key:064x}")
    # should be 0x5712f72ca98165625fe652f1911e7e5795a86d56e724f7cd4bf3375c5fcc26b8

    print(f"\r\n\r\nUsing the cracked private key to sign")
    raw_int_3_to_sign = string_to_int(hashlib.sha256(b"admin").digest())
    r, s = ec_curve.ecdsa_sign(cracked_priv_key, raw_int_3_to_sign, k)
    print(f"ECDSA signature for 0x{raw_int_3_to_sign:064x}: ")
    print(f"(r = 0x{r:064x}, s=0x{s:064x})")
    # r should be: 0x2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
    # s should be: 0x9c99411b74e3bc2d6ffc3b86530dc3e135402567104c146aeb4581772e518a9c

    print("\r\n\r\nVerifying ECDSA signature")
    public_key_point = ec_curve.EC_multiply(ec_curve.point_generator, cracked_priv_key)
    signature_verify_result = ec_curve.ecdsa_verify(public_key_point, raw_int_3_to_sign, (r, s))
    print(f"Signature: (r = 0x{r:064x}, s=0x{s:064x})")
    print(f"Raw int to sign: 0x{raw_int_3_to_sign:064x}")
    print(f"Verifying result: {signature_verify_result}")

if __name__ == '__main__':
    secp256k1_demo()