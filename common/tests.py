#!/usr/bin/env python3

from tasks.gfmul import gfmul
from tasks.poly import block2poly, poly2block
from tasks.sea import sea_enc, sea_dec
from tasks.xex import XEX

def test_gfmul() -> None:
    element_1 = "ARIAAAAAAAAAAAAAAAAAgA=="
    element_2 = "AgAAAAAAAAAAAAAAAAAAAA=="
    result = "hSQAAAAAAAAAAAAAAAAAAA=="
    assert gfmul(element_1, element_2) == result
    print(f"GFMUL test result is: {result}")

def test_poly2block() -> None:
    coefficients = [12, 127, 9, 0]
    result = "ARIAAAAAAAAAAAAAAAAAgA=="
    p2b_instance = poly2block(coefficients)
    res = p2b_instance.p2b()
    assert res == result
    print(f"Poly2block test result is: {res}")

def test_block2poly() -> None:
    block = "ARIAAAAAAAAAAAAAAAAAgA=="
    result = [0, 9, 12, 127]
    b2p_instance = block2poly(block)
    res = b2p_instance.b2p()
    assert res == result
    print(f"Block2poly test result is: {res}")

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


def tests_run() -> None:
    test_block2poly()
    test_poly2block()
    test_gfmul()
    test_sea_enc()
    test_sea_dec()
    test_xex_enc()
    test_xex_dec()

def main():
    tests_run()
if __name__ == "__main__":
   tests_run() 
