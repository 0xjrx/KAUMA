#!/usr/bin/env python3
import pstats
import cProfile
import base64
from tasks.gfmul import gfmul
from tasks.poly import block2poly, poly2block, poly2block_gcm, block2poly_gcm
from tasks.sea import sea_enc, sea_dec
from tasks.xex import XEX
from tasks.gcm import GCM_encrypt, GCM_decrypt
from tasks.polynom import FieldElement, Polynom
from tasks.gcm_pwn import sff, ddf, edf

def test_gfmul() -> None:
    element_1 = "ARIAAAAAAAAAAAAAAAAAgA=="
    element_2 = "AgAAAAAAAAAAAAAAAAAAAA=="
    result = "hSQAAAAAAAAAAAAAAAAAAA=="
    assert gfmul(element_1, element_2) == result
    print(f"GFMUL test result is: {result}")

def test_poly2block() -> None:
    coefficients = [12, 127, 9, 0]
    result = "ARIAAAAAAAAAAAAAAAAAgA=="
    res = poly2block(coefficients)
    assert res == result
    print(f"Poly2block test result is: {res}")

def test_poly2block_gcm() -> None:
    coefficients = [12, 127, 9, 0]
    result = "gEgAAAAAAAAAAAAAAAAAAQ=="
    res = poly2block_gcm(coefficients)
    assert res == result
    print(f"Poly2block_gcm test result is: {res}")

    
def test_block2poly() -> None:
    block = "ARIAAAAAAAAAAAAAAAAAgA=="
    result = [0, 9, 12, 127]
    res = block2poly(block)
    assert res == result
    print(f"Block2poly test result is: {res}")

def test_block2poly_gcm() -> None:
    block = "gEgAAAAAAAAAAAAAAAAAAQ=="
    result = [0, 9, 12, 127]
    res = block2poly_gcm(block)
    assert res == result
    print(f"Block2poly_gcm test result is: {res}")


def test_sea_enc() -> None:
    key = "istDASeincoolerKEYrofg=="
    input = "yv66vvrO263eyviIiDNEVQ=="
    result = "D5FDo3iVBoBN9gVi9/MSKQ=="
    assert sea_enc(key, input) == result
    print(f"Sea Encrypt test result is: {result}")

def test_sea_dec() -> None:
    key = "istDASeincoolerKEYrofg=="
    input = "D5FDo3iVBoBN9gVi9/MSKQ=="
    result = "yv66vvrO263eyviIiDNEVQ=="
    assert sea_dec(key, input) == result
    print(f"Sea decrypt test result is: {result}")

def test_xex_enc() -> None:
    key = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
    tweak = "6VXORr+YYHrd2nVe0OlA+Q=="
    input = "/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW"
    result = "mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO"
    xex_inst = XEX(key, tweak, input)
    assert xex_inst.xex_round_enc() == result
    print(f"XEX encrypt test result is: {result}")

def test_xex_dec() -> None:
    key = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
    tweak = "6VXORr+YYHrd2nVe0OlA+Q=="
    input = "lr/ItaYGFXCtHhdPndE65yg7u/GIdM9wscABiiFOUH2Sbyc2UFMlIRSMnZrYCW1a"
    xex_inst = XEX(key, tweak, input)
    result = "SGV5IHdpZSBrcmFzcyBkYXMgZnVua3Rpb25pZXJ0IGphIG9mZmVuYmFyIGVjaHQu"
    assert xex_inst.xex_round_dec() == result
    print(f"XEX decrypt test result is: {result}")

def test_gfmul_arbitrary() -> None:
    element_1 = "AwEAAAAAAAAAAAAAAAAAgA=="
    element_2 = "oBAAAAAAAAAAAAAAAAAAAA=="
    result = "UIAUAAAAAAAAAAAAAAAAAA=="
    assert gfmul(element_1, element_2) == result
    print(f"Result for arbitrary gfmul is {result}")
def test_gcm_enc() -> None:
    nonce = "4gF+BtR3ku/PUQci"
    key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
    plaintext = "RGFzIGlzdCBlaW4gVGVzdA=="
    ad = "QUQtRGF0ZW4="
    result = {"ciphertext": "ET3RmvH/Hbuxba63EuPRrw==","tag": "Mp0APJb/ZIURRwQlMgNN/w==","L": "AAAAAAAAAEAAAAAAAAAAgA==","H": "Bu6ywbsUKlpmZXMQyuGAng=="}
    assert GCM_encrypt(nonce, key, plaintext,ad, "aes") == result
    print("AES GCM encryption successful")
def test_gcm_enc_sea() -> None:
    nonce = "4gF+BtR3ku/PUQci"
    key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
    plaintext = "RGFzIGlzdCBlaW4gVGVzdA=="
    ad = "QUQtRGF0ZW4="
    result = {"ciphertext": "0cI/Wg4R3URfrVFZ0hw/vg==","tag": "ysDdzOSnqLH0MQ+Mkb23gw==","L": "AAAAAAAAAEAAAAAAAAAAgA==","H": "xhFcAUT66qWIpYz+Ch5ujw=="}
    print(GCM_encrypt(nonce, key, plaintext,ad,"sea"))
    assert GCM_encrypt(nonce, key, plaintext,ad,"sea") == result
    print("AES GCM sea encryption successful")
def test_gcm_dec() -> None:
    nonce = "4gF+BtR3ku/PUQci"
    key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
    ciphertext = "ET3RmvH/Hbuxba63EuPRrw=="
    ad = "QUQtRGF0ZW4="
    tag = "Mp0APJb/ZIURRwQlMgNN/w=="
    result = {"authentic": True, "plaintext":"RGFzIGlzdCBlaW4gVGVzdA=="}
    assert GCM_decrypt(nonce, key, ciphertext,ad, tag,"aes" ) == result
    print("AES GCMdecryption successful")
def test_gcm_enc_ad() -> None:
    nonce = "yv66vvrO263eyviI"
    key = "/v/pkoZlcxxtao+UZzCDCA=="
    plaintext = "2TEyJfiEBuWlWQnFr/UmmoanqVMVNPfaLkwwPYoxinIcPAyVlWgJUy/PDiRJprUlsWrt9aoN5le6Y3s5"
    ad = "/u36zt6tvu/+7frO3q2+76ut2tI="
    result = {"ciphertext": "QoMewiF3dCRLciG3hNDUnOOqIS8sAqTgNcF+IymsoS4h1RSyVGaTHH2PalqshKoFG6MLOWoKrJc9WOCR","tag": "W8lPvDIhpduU+ula5xIaRw==","L": "AAAAAAAAAKAAAAAAAAAB4A==","H": "uDtTNwi/U10KpuUpgNU7eA=="}
    assert GCM_encrypt(nonce, key, plaintext, ad, "aes") == result
    print("GCM Edge case successful\n")

def test_gfpoly_add():
    a = [
        "NeverGonnaGiveYouUpAAA==",
        "NeverGonnaLetYouDownAA==",
        "NeverGonnaRunAroundAAA==",
        "AndDesertYouAAAAAAAAAA=="
        ]    
    b = [
    "KryptoanalyseAAAAAAAAA==",
    "DHBWMannheimAAAAAAAAAA=="
    ]    
    a_poly = Polynom(a)
    b_poly = Polynom(b)
    res = {"S":(a_poly + b_poly).polynomials}
    result = {"S":[
    "H1d3GuyA9/0OxeYouUpAAA==",
    "OZuIncPAGEp4tYouDownAA==",
    "NeverGonnaRunAroundAAA==",
    "AndDesertYouAAAAAAAAAA=="
    ]}
    assert res == result
    print(f"Poly_add successful. Result is: {res}\n")

def test_gfpoly_mul():
    a =[ 
    "JAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "ACAAAAAAAAAAAAAAAAAAAA=="
    ]
    b = [
    "0AAAAAAAAAAAAAAAAAAAAA==",
    "IQAAAAAAAAAAAAAAAAAAAA=="
    ]
    a_poly = Polynom(a)
    b_poly = Polynom(b)
    res = {"P":(a_poly * b_poly).polynomials}
    result = {"P": [
    "MoAAAAAAAAAAAAAAAAAAAA==",
    "sUgAAAAAAAAAAAAAAAAAAA==",
    "MbQAAAAAAAAAAAAAAAAAAA==",
    "AAhAAAAAAAAAAAAAAAAAAA=="
    ]}
    assert res == result
    print(f"Poly_mul successful, result is: {res}\n")

def test_gfpoly_pow():
    a = [
    "JAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "ACAAAAAAAAAAAAAAAAAAAA=="
    ]    
    a_poly = Polynom(a)
    k = 3
    res =  {"Z":(a_poly**k).polynomials}
    result = {
    "Z": [
    "AkkAAAAAAAAAAAAAAAAAAA==",
    "DDAAAAAAAAAAAAAAAAAAAA==",
    "LQIIAAAAAAAAAAAAAAAAAA==",
    "8AAAAAAAAAAAAAAAAAAAAA==",
    "ACgCQAAAAAAAAAAAAAAAAA==",
    "AAAMAAAAAAAAAAAAAAAAAA==",
    "AAAAAgAAAAAAAAAAAAAAAA=="
    ]
    }
    assert res == result
    print(f"Gfpoly_pow successful, result is {res}")

def test_gfdiv():
    a = "JAAAAAAAAAAAAAAAAAAAAA=="
    b = "wAAAAAAAAAAAAAAAAAAAAA=="
    a_fe = FieldElement(int.from_bytes(base64.b64decode(a), 'little'))
    b_fe = FieldElement(int.from_bytes(base64.b64decode(b), 'little'))
    c = a_fe / b_fe
    res = {"q": base64.b64encode(int.to_bytes(int(c), 16, 'little')).decode('utf-8')}
    result = {
    "q": "OAAAAAAAAAAAAAAAAAAAAA=="
    }
    assert res ==result
    print(f"Gfiv successful, result is: {res}\n")
def test_gfpoly_divmod():
    A = Polynom([
    "JAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "ACAAAAAAAAAAAAAAAAAAAA=="
    ])
    B = Polynom([
    "0AAAAAAAAAAAAAAAAAAAAA==",
    "IQAAAAAAAAAAAAAAAAAAAA=="
    ])
    quotient, remainder = A/B
    res = {"Q": quotient.polynomials, "R": remainder.polynomials}
    result = {
    "Q": [
    "nAIAgCAIAgCAIAgCAIAgCg==",
    "m85znOc5znOc5znOc5znOQ=="
    ],
    "R": [
    "lQNA0DQNA0DQNA0DQNA0Dg=="
    ]
    }
    assert res == result
    print(f"Gfpoly_divmod successful, result is: {res}\n")

def test_gfpoly_powmod():
    A = Polynom([
    "JAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "ACAAAAAAAAAAAAAAAAAAAA=="
    ])
    B = Polynom([
    "KryptoanalyseAAAAAAAAA==",
    "DHBWMannheimAAAAAAAAAA=="
    ])
    k = 1000
    re = A.poly_powmod(B, k)
    res =  {"Z":re.polynomials}
    result = {
    "Z": [
    "oNXl5P8xq2WpUTP92u25zg=="
    ]}
    assert res == result
    print(f"Powmod successful, result is: {res}\n")

def test_gfpoly_sort():
    polys = [
    [
    "NeverGonnaGiveYouUpAAA==",
    "NeverGonnaLetYouDownAA==",
    "NeverGonnaRunAroundAAA==",
    "AndDesertYouAAAAAAAAAA=="
    ],
    [
    "WereNoStrangersToLoveA==",
    "YouKnowTheRulesAAAAAAA==",
    "AndSoDoIAAAAAAAAAAAAAA=="
    ],
    [
    "NeverGonnaMakeYouCryAA==",
    "NeverGonnaSayGoodbyeAA==",
    "NeverGonnaTellALieAAAA==",
    "AndHurtYouAAAAAAAAAAAA=="
    ]]
    polys_obj = [Polynom(group) for group in polys]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    sorted_polynomials_representation = [p.polynomials for p in sorted_polynomials]
    res = {"sorted_polys": sorted_polynomials_representation}
    result = {
    "sorted_polys": [
    [
    "WereNoStrangersToLoveA==",
    "YouKnowTheRulesAAAAAAA==",
    "AndSoDoIAAAAAAAAAAAAAA=="
    ],
    [
    "NeverGonnaMakeYouCryAA==",
    "NeverGonnaSayGoodbyeAA==",
    "NeverGonnaTellALieAAAA==",
    "AndHurtYouAAAAAAAAAAAA=="
    ],
    [
    "NeverGonnaGiveYouUpAAA==",
    "NeverGonnaLetYouDownAA==",
    "NeverGonnaRunAroundAAA==",
    "AndDesertYouAAAAAAAAAA=="
    ]
    ]
    }
    assert res == result
    print(f"Polysort successful, result is: {res}\n")

def test_gfpoly_makemonic():
    poly = Polynom([
    "NeverGonnaGiveYouUpAAA==",
    "NeverGonnaLetYouDownAA==",
    "NeverGonnaRunAroundAAA==",
    "AndDesertYouAAAAAAAAAA=="
    ])
    monic_poly = poly.gfpoly_makemonic()
    res = {"A*": monic_poly}
    result = {
    "A*": [
    "edY47onJ4MtCENDTHG/sZw==",
    "oaXjCKnceBIxSavZ9eFT8w==",
    "1Ial5rAJGOucIdUe3zh5bw==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ]
    }
    assert res == result 
    print(f"Makemonic successful, result is: {res}\n")

def test_gfpoly_sqrt():
    poly = Polynom([
    "5TxUxLHO1lHE/rSFquKIAg==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "0DEUJYdHlmd4X7nzzIdcCA==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "PKUa1+JHTxHE8y3LbuKIIA==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "Ds96KiAKKoigKoiKiiKAiA=="
    ])
    poly_sqrt = poly.sqrt()
    res = {"S": poly_sqrt.polynomials}
    result = {
    "S": [
    "NeverGonnaGiveYouUpAAA==",
    "NeverGonnaLetYouDownAA==",
    "NeverGonnaRunAroundAAA==",
    "AndDesertYouAAAAAAAAAA=="
    ]
    }
    assert res == result
    print(f"Sqrt successful, result is: {res}\n")

def test_gfpoly_diff():
    poly = Polynom([
    "IJustWannaTellYouAAAAA==",
    "HowImFeelingAAAAAAAAAA==",
    "GottaMakeYouAAAAAAAAAA==",
    "UnderstaaaaaaaaaaaaanQ=="
    ])
    derivative = poly.derivative()
    res = {"F'": derivative.polynomials}
    result = {
    "F'": [
    "HowImFeelingAAAAAAAAAA==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "UnderstaaaaaaaaaaaaanQ=="
    ]
    }
    assert res == result
    print(f"Poly diff successful, result is: {res}\n")

def test_gfpoly_gcd():
    f = Polynom([
    "DNWpXnnY24XecPa7a8vrEA==",
    "I8uYpCbsiPaVvUznuv1IcA==",
    "wsbiU432ARWuO93He3vbvA==",
    "zp0g3o8iNz7Y+8oUxw1vJw==",
    "J0GekE3uendpN6WUAuJ4AA==",
    "wACd0e6u1ii4AAAAAAAAAA==",
    "ACAAAAAAAAAAAAAAAAAAAA=="
    ])
    g = Polynom([
    "I20VjJmlSnRSe88gaDiLRQ==",
    "0Cw5HxJm/pfybJoQDf7/4w==",
    "8ByrMMf+vVj5r3YXUNCJ1g==",
    "rEU/f2UZRXqmZ6V7EPKfBA==",
    "LfdALhvCrdhhGZWl9l9DSg==",
    "KSUKhN0n6/DZmHPozd1prw==",
    "DQrRkuA9Zx279wAAAAAAAA==",
    "AhCEAAAAAAAAAAAAAAAAAA=="
    ])
    re = f.gcd(g)
    res = {"G": re.polynomials}
    result = {
    "G": [
    "NeverGonnaMakeYouCryAA==",
    "NeverGonnaSayGoodbyeAA==",
    "NeverGonnaTellALieAAAA==",
    "AndHurtYouAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ]
    }
    assert res == result
    print(f"GCD successful, result is: {res}\n")

def test_gfpoly_factor_sff():
    f = Polynom([
    "vL77UwAAAAAAAAAAAAAAAA==",
    "mEHchYAAAAAAAAAAAAAAAA==",
    "9WJa0MAAAAAAAAAAAAAAAA==",
    "akHfwWAAAAAAAAAAAAAAAA==",
    "E12o/QAAAAAAAAAAAAAAAA==",
    "vKJ/FgAAAAAAAAAAAAAAAA==",
    "yctWwAAAAAAAAAAAAAAAAA==",
    "c1BXYAAAAAAAAAAAAAAAAA==",
    "o0AtAAAAAAAAAAAAAAAAAA==",
    "AbP2AAAAAAAAAAAAAAAAAA==",
    "k2YAAAAAAAAAAAAAAAAAAA==",
    "vBYAAAAAAAAAAAAAAAAAAA==",
    "dSAAAAAAAAAAAAAAAAAAAA==",
    "69gAAAAAAAAAAAAAAAAAAA==",
    "VkAAAAAAAAAAAAAAAAAAAA==",
    "a4AAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ])
    result = {"factors":sff(f)}
    res = {
    "factors": [
    {
    "factor": [
    "q4AAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ],
    "exponent": 1
    },
    {
    "factor": [
    "iwAAAAAAAAAAAAAAAAAAAA==",
    "CAAAAAAAAAAAAAAAAAAAAA==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ],
    "exponent": 2
    },
    {
    "factor": [
    "kAAAAAAAAAAAAAAAAAAAAA==",
    "CAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ],
    "exponent": 3
    }
    ]
    }
    assert res == result
    print(f"SFF works, result is: {result}\n")
   
def test_gfpoly_factor_ddf():
    f = Polynom([
"tpkgAAAAAAAAAAAAAAAAAA==",
"m6MQAAAAAAAAAAAAAAAAAA==",
"8roAAAAAAAAAAAAAAAAAAA==",
"3dUAAAAAAAAAAAAAAAAAAA==",
"FwAAAAAAAAAAAAAAAAAAAA==",
"/kAAAAAAAAAAAAAAAAAAAA==",
"a4AAAAAAAAAAAAAAAAAAAA==",
"gAAAAAAAAAAAAAAAAAAAAA=="
])
    result = {"factors":ddf(f)}
    res = {"factors": [{
"factor": [
"q4AAAAAAAAAAAAAAAAAAAA==",
"gAAAAAAAAAAAAAAAAAAAAA=="
],
"degree": 1
},
{
"factor": [
"mmAAAAAAAAAAAAAAAAAAAA==",
"AbAAAAAAAAAAAAAAAAAAAA==",
"zgAAAAAAAAAAAAAAAAAAAA==",
"FwAAAAAAAAAAAAAAAAAAAA==",
"AAAAAAAAAAAAAAAAAAAAAA==",
"wAAAAAAAAAAAAAAAAAAAAA==",
"gAAAAAAAAAAAAAAAAAAAAA=="
],
"degree": 3
}
]
}    
    assert res == result
    print(f"DDF works, result is: {result}\n")

def test_gfpoly_factor_edf()-> None:
    d = 3
    F = Polynom([
          "mmAAAAAAAAAAAAAAAAAAAA==",
          "AbAAAAAAAAAAAAAAAAAAAA==",
          "zgAAAAAAAAAAAAAAAAAAAA==",
          "FwAAAAAAAAAAAAAAAAAAAA==",
          "AAAAAAAAAAAAAAAAAAAAAA==",
          "wAAAAAAAAAAAAAAAAAAAAA==",
          "gAAAAAAAAAAAAAAAAAAAAA=="])
    res = edf(F,d)
    result = {
    "factors": [
    [
    "iwAAAAAAAAAAAAAAAAAAAA==",
    "CAAAAAAAAAAAAAAAAAAAAA==",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ],
    [
    "kAAAAAAAAAAAAAAAAAAAAA==",
    "CAAAAAAAAAAAAAAAAAAAAA==",
    "wAAAAAAAAAAAAAAAAAAAAA==",
    "gAAAAAAAAAAAAAAAAAAAAA=="
    ]
    ]
    }
    assert res == result

    print(f"EDF works, result is: {res}\n")

def tests_run() -> None:
    test_block2poly()
    test_poly2block()
    test_gfmul()
    test_sea_enc()
    test_sea_dec()
    test_xex_enc()
    test_xex_dec()
    test_gfmul_arbitrary()
    test_poly2block_gcm()
    test_block2poly_gcm()
    test_gcm_enc()
    test_gcm_dec()
    test_gcm_enc_ad()
    test_gcm_enc_sea()
    test_gfpoly_add()
    test_gfpoly_mul()
    test_gfpoly_pow()
    test_gfdiv()
    test_gfpoly_divmod()
    test_gfpoly_powmod()
    test_gfpoly_sort()
    test_gfpoly_makemonic()
    test_gfpoly_sqrt()
    test_gfpoly_diff()
    test_gfpoly_gcd()
    test_gfpoly_factor_sff()
    test_gfpoly_factor_ddf()
if __name__ == "__main__":
    profiler = cProfile.Profile()
    profiler.enable()
    tests_run()
    profiler.disable()
    include_paths = ["common", "tasks"]
    stats = pstats.Stats(profiler)
    ##stats.strip_dirs()
    stats.sort_stats("time")
    stats.print_stats("tests.py")

