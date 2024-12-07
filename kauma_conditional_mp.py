#!/usr/bin/env python3

import json
from tasks.poly import block2poly, poly2block, block2poly_gcm, poly2block_gcm
from common.common import stderr_write
import multiprocessing as mp
from tasks.gfmul import gfmul
from tasks.sea import sea_enc, sea_dec
from tasks.xex import XEX
from tasks.gcm import GCM_encrypt,  GCM_decrypt
from tasks.padding_oracle_crack import padding_oracle_crack
from tasks.polynom import FieldElement, Polynom
from tasks.gcm_pwn import sff, ddf, edf
import time, base64
from argparse import ArgumentParser

def process_test_case(test_case, test_case_id):    
    action = test_case.get("action")
    arguments = test_case.get("arguments")
    
    result = {}
    try:        
        match action:
            case "poly2block":
                result = handle_p2b(arguments)
            case "block2poly":
                result = handle_b2p(arguments)
            case "gfmul":
                result = handle_gfmul(arguments)
            case "sea128":
                result = handle_sea(arguments)
            case "xex":
                result = handle_xex(arguments)
            case "gcm_encrypt":
                result = handle_gcm_encrypt(arguments)
            case "gcm_decrypt":
                result = handle_gcm_decrypt(arguments)
            case "padding_oracle":
                result = handle_po(arguments)
            case "gfpoly_add":
                result = handle_gfpoly_add(arguments)
            case "gfpoly_mul":
                result = handle_gfpoly_mul(arguments)
            case "gfpoly_pow":
                result = handle_gfpoly_pow(arguments)
            case "gfpoly_divmod":
                result = handle_gfpoly_divmod(arguments)
            case "gfdiv":
                result = handle_gfdiv(arguments)
            case "gfpoly_powmod":
                result = handle_gfpoly_powmod(arguments)
            case "gfpoly_sort":
                result = handle_gfpoly_sort(arguments)
            case "gfpoly_make_monic":
                result = handle_gfpoly_makemonic(arguments)
            case "gfpoly_sqrt":
                result = handle_gfpoly_sqrt(arguments)
            case "gfpoly_diff":
                result = handle_gfpoly_diff(arguments)
            case "gfpoly_gcd":
                result = handle_gfpoly_gcd(arguments)
            case "gfpoly_factor_sff":
                result = handle_gfpoly_factor_sff(arguments)
            case "gfpoly_factor_ddf":
                result = handle_gfpoly_factor_ddf(arguments)
            case "gfpoly_factor_edf":
                result = handle_gfpoly_factor_edf(arguments)
            case _:
                stderr_write(f"Unknown error for {action} with ID:{test_case_id}")
        return test_case_id, result
    
    except Exception as e:
        stderr_write(f"Error processing test case {test_case_id}: {str(e)}")
        return test_case_id, {"error": str(e)}    

def handle_p2b(arguments):
    if arguments["semantic"] == "xex":
        result = poly2block(arguments["coefficients"]) 
        return {"block": result}
    if arguments["semantic"] == "gcm":
        coefficients = arguments["coefficients"]
        block = poly2block_gcm(coefficients)
        return {"block": block}
def handle_b2p(arguments):
    if arguments["semantic"] == "xex":
        result = block2poly(arguments["block"])
        return {"coefficients":result}
    if arguments["semantic"] == "gcm":
        block = arguments["block"]
        poly = block2poly_gcm(block)
        return {"coefficients":poly}
def handle_gfmul(arguments):
    if arguments["semantic"] == 'xex':
        a = arguments["a"]
        b = arguments["b"]
        res = gfmul(a,b)
        return {"product":res}
    if arguments["semantic"] == 'gcm':
        a = arguments["a"]
        b = arguments["b"]
        a_fe = FieldElement(int.from_bytes(base64.b64decode(a), 'little'))
        b_fe = FieldElement(int.from_bytes(base64.b64decode(b), 'little'))
        res = (a_fe*b_fe).element
        return {"product":base64.b64encode(int.to_bytes(res,16, 'little')).decode('utf-8')}
def handle_sea(arguments):
    if arguments["mode"] =='encrypt':
        key = arguments["key"]
        input = arguments["input"]
        res = sea_enc(key, input)
        return {"output":res}
    if arguments["mode"] =='decrypt':
        key = arguments["key"]
        input = arguments["input"]
        res = sea_dec(key, input)
        return {"output":res}
def handle_xex(arguments):
    if arguments["mode"] == 'encrypt':
        key = arguments["key"]
        tweak = arguments["tweak"]
        input = arguments["input"]
        xex_instance = XEX(key, tweak, input)
        res = xex_instance.xex_round_enc()
        return {"output": res}
    if arguments["mode"] == 'decrypt':
        key = arguments["key"]
        tweak = arguments["tweak"]
        input = arguments["input"]
        xex_instance = XEX(key, tweak, input)
        res = xex_instance.xex_round_dec()
        return {"output": res}
def handle_gcm_encrypt(arguments):
    if arguments["algorithm"] == 'aes128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        plaintext = arguments["plaintext"]
        associated_data = arguments["ad"]
        return GCM_encrypt(nonce, key, plaintext, associated_data, "aes")
    if arguments["algorithm"] == 'sea128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        plaintext = arguments["plaintext"]
        associated_data = arguments["ad"]
        return GCM_encrypt(nonce, key, plaintext, associated_data, "sea")
def handle_gcm_decrypt(arguments):
    if arguments["algorithm"] == 'aes128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        ciphertext = arguments["ciphertext"]
        associated_data = arguments["ad"]
        tag = arguments["tag"]
        return GCM_decrypt(nonce, key, ciphertext, associated_data, tag, "aes")
    if arguments["algorithm"] == 'sea128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        ciphertext = arguments["ciphertext"]
        associated_data = arguments["ad"]
        tag = arguments["tag"]
        return GCM_decrypt(nonce, key, ciphertext, associated_data, tag, "sea") 
def handle_po(arguments):
    hostname = arguments["hostname"]
    port = arguments["port"]
    iv = base64.b64decode(arguments["iv"])
    ct = base64.b64decode(arguments["ciphertext"])
    result = padding_oracle_crack(hostname, port, iv, ct)
    return {"plaintext": result}
def handle_gfpoly_add(arguments):
    a = arguments["A"]
    b = arguments["B"]
    a_poly = Polynom(a)
    b_poly = Polynom(b)
    res = (a_poly + b_poly).polynomials
    return {"S":res}
def handle_gfpoly_mul(arguments):
    a = arguments["A"] 
    b = arguments["B"] 
    a_poly = Polynom(a)
    b_poly = Polynom(b)
    res = (a_poly * b_poly).polynomials
    return {"P":res}
def handle_gfpoly_pow(arguments):
    a = arguments["A"]
    a_poly = Polynom(a)
    k = arguments["k"]
    res = (a_poly**k).polynomials
    return {"Z": res}
def handle_gfdiv(arguments):
    a = arguments["a"]
    b = arguments["b"]
    a_fe = FieldElement(int.from_bytes(base64.b64decode(a), 'little'))
    b_fe = FieldElement(int.from_bytes(base64.b64decode(b), 'little'))
    c = a_fe / b_fe
    return {"q": base64.b64encode(int.to_bytes(int(c), 16, 'little')).decode('utf-8')}
def handle_gfpoly_divmod(arguments):
    A = Polynom(arguments["A"])
    B = Polynom(arguments["B"])
    quotient, remainder = A/B
    return {"Q": quotient.polynomials, "R": remainder.polynomials}
def handle_gfpoly_powmod(arguments):
    A = Polynom(arguments["A"])
    B = Polynom(arguments["M"])
    k = arguments["k"]
    result = A.poly_powmod(B, k)
    return {"Z":result.polynomials}
def handle_gfpoly_sort(arguments):
    polys = arguments["polys"]
    polys_obj = [Polynom(group) for group in polys]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    sorted_polynomials_representation = [p.polynomials for p in sorted_polynomials]
    return {"sorted_polys": sorted_polynomials_representation}
def handle_gfpoly_makemonic(arguments):
    poly = Polynom(arguments["A"])
    monic_poly = poly.gfpoly_makemonic()
    return {"A*": monic_poly}
def handle_gfpoly_sqrt(arguments):
    poly = Polynom(arguments["Q"])
    poly_sqrt = poly.sqrt()
    return {"S": poly_sqrt.polynomials}
def handle_gfpoly_diff(arguments):
    poly = Polynom(arguments["F"])
    derivative = poly.derivative()
    return {"F'": derivative.polynomials}
def handle_gfpoly_gcd(arguments):
    f = Polynom(arguments["A"])
    g = Polynom(arguments["B"])
    result = f.gcd(g)
    return {"G": result.polynomials}
def handle_gfpoly_factor_sff(arguments):
    f = Polynom(arguments["F"])
    result = {"factors": sff(f)}
    return result
def handle_gfpoly_factor_ddf(arguments):
    f = Polynom(arguments["F"])
    result = {"factors": ddf(f)}
    return result
def handle_gfpoly_factor_edf(arguments):
    f = Polynom(arguments["F"])
    d = arguments["d"]
    result = edf(f,d)
    return {"factors": result}

class ParseJson:
    def __init__(self, filename):
        self.filename = filename
        self.results = {"responses":{}}
        self.timing_info = {}

    def parse(self):
        try:
            total_start = time.time()
            
            file_start = time.time()
            with open(self.filename, 'r') as file:
                data = json.load(file)
            file_time = time.time() - file_start
            
            process_start = time.time()
            processing_method = "conditional"
            self._parse_parallel(data)
            process_time = time.time() - process_start
            
            total_time = time.time() - total_start
            
            stderr_write("\nTiming Information:")
            stderr_write(f"Total Execution Time: {total_time:.3f} seconds")
            stderr_write(f"File Loading Time: {file_time:.3f} seconds")
            stderr_write(f"Processing Time: {process_time:.3f} seconds")
            stderr_write(f"Processing Method: {processing_method}")
            stderr_write(f"Number of Test Cases: {len(data['testcases'])}\n")
            
            print(json.dumps(self.results))   

        except KeyError as e:
            stderr_write(f"Missing key in given Testfile {e}")
        except json.JSONDecodeError:
            stderr_write("Error: Failed to decode the file given")
    
    def _parse_parallel(self, data):
        stderr_write("Used conditional parallel processing")
        
        # Separate test cases that need multiprocessing
        parallel_cases = []
        sequential_cases = []
        ordered_results = {}

        for test_case_id, test_case in data["testcases"].items():
            if test_case.get("action") in {"padding_oracle, gfpoly_pow, gfpoly_factor_sff", "gfpoly_factor_ddf, gfpoly_factor_edf"}:
                parallel_cases.append((test_case, test_case_id))
            else:
                sequential_cases.append((test_case, test_case_id))
        
        # Process parallel cases using multiprocessing
        if parallel_cases:
            num_cores = mp.cpu_count()
            pool = mp.Pool(processes=num_cores)
            results = pool.starmap(process_test_case, parallel_cases)
            pool.close()
            pool.join()
            for test_case_id, result in results:
                ordered_results[test_case_id] = result
        
        # Process sequential cases
        for test_case, test_case_id in sequential_cases:
            test_case_id, result = process_test_case(test_case, test_case_id)
            ordered_results[test_case_id] = result
        
        # Collect results in the order of the input file
        for test_case_id in data["testcases"]:
            self.results["responses"][test_case_id] = ordered_results[test_case_id]

def get_args():
    parser = ArgumentParser()
    parser.add_argument('file', action='store', help='Specify json file')
    return parser.parse_args()
        
def main():
    try:
        args = get_args()
        parser = ParseJson(args.file)
        parser.parse()
    except ValueError as e:
        stderr_write(f"Error: {e}")

if __name__ == "__main__":
    mp.set_start_method('spawn')
    main()

