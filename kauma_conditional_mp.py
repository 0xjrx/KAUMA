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
from tasks.polynom_perf import FieldElement
from tasks.gcm_pwn import sff, ddf, edf
import time, base64
from argparse import ArgumentParser
from common import _base64_to_poly, poly_to_b64, transform_sort, gcm_sem



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
        a = int.from_bytes(base64.b64decode(arguments["a"]), 'little')
        b = int.from_bytes(base64.b64decode(arguments["b"]), 'little')
        a_gcm, b_gcm = FieldElement(gcm_sem(a)), FieldElement(gcm_sem(b))
        res = (a_gcm*b_gcm).element
        res_gcm = gcm_sem(res)
        return {"product":base64.b64encode(int.to_bytes(res_gcm,16, 'little')).decode('utf-8')}
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
    a = _base64_to_poly(arguments["A"])
    b = _base64_to_poly(arguments["B"])
    res = poly_to_b64((a + b).int)
    return {"S":res}

def handle_gfpoly_mul(arguments):
    a = _base64_to_poly(arguments["A"] )
    b = _base64_to_poly(arguments["B"] )
    res = poly_to_b64((a * b).int)
    return {"P":res}

def handle_gfpoly_pow(arguments):
    a = _base64_to_poly(arguments["A"])
    k = arguments["k"]
    res = poly_to_b64((a**k).int)
    return {"Z": res}

def handle_gfdiv(arguments):
    a = int.from_bytes(base64.b64decode(arguments["a"]), 'little')
    b = int.from_bytes(base64.b64decode(arguments["b"]), 'little')
    x = FieldElement(0)
    a_ = x.gcm_sem(a)
    b_ = x.gcm_sem(b)
    c = FieldElement(a_)/FieldElement(b_)
    c_ = c.gcm_sem(c.element)
    return {"q": base64.b64encode(int.to_bytes(c_, 16, 'little')).decode('utf-8')}

def handle_gfpoly_divmod(arguments):
    A = _base64_to_poly(arguments["A"])
    B = _base64_to_poly(arguments["B"])
    quotient, remainder = A/B
    res = poly_to_b64(quotient.int)
    res_ = poly_to_b64(remainder.int)
    return {"Q": res, "R": res_}

def handle_gfpoly_powmod(arguments):
    A = _base64_to_poly(arguments["A"])
    B = _base64_to_poly(arguments["M"])
    k = arguments["k"]
    result = poly_to_b64((A.poly_powmod(B, k)).int)
    return {"Z":result}

def handle_gfpoly_sort(arguments):
    polys = arguments["polys"]
    polys_obj = [_base64_to_poly(group) for group in polys]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    sorted_polynomials_representation = [poly_to_b64(p.int) for p in sorted_polynomials]
    return {"sorted_polys": sorted_polynomials_representation}

def handle_gfpoly_makemonic(arguments):
    poly = _base64_to_poly(arguments["A"])
    monic_poly = poly.gfpoly_makemonic()
    res = poly_to_b64(monic_poly)
    return {"A*": res}

def handle_gfpoly_sqrt(arguments):
    poly = _base64_to_poly(arguments["Q"])
    poly_sqrt = poly.sqrt()
    res = poly_to_b64(poly_sqrt.int)
    return {"S": res}

def handle_gfpoly_diff(arguments):
    poly = _base64_to_poly(arguments["F"])
    derivative = poly.derivative()
    res = poly_to_b64(derivative.int)
    return {"F'": res}

def handle_gfpoly_gcd(arguments):
    f = _base64_to_poly(arguments["A"])
    g = _base64_to_poly(arguments["B"])
    res_ = (f.gcd(g).int)
    result = poly_to_b64(res_)
    return {"G": result}



def handle_gfpoly_factor_sff(arguments):
    f = _base64_to_poly(arguments["F"])
    result = sff(f)
    transformed_data = transform_sort(result, "exponent") 
    return {"factors":transformed_data}
def handle_gfpoly_factor_ddf(arguments):
    f = _base64_to_poly(arguments["F"])
    result = ddf(f)
    transformed = transform_sort(result, "degree")
    result = {"factors": transformed}
    
    return result

def handle_gfpoly_factor_edf(arguments):
    f = _base64_to_poly(arguments["F"])
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
        
        parallel_cases = []
        sequential_cases = []

        for test_case_id, test_case in data["testcases"].items():
            if test_case.get("action") in {"block2poly", "poly2block","gfmul", "handle_gfpoly_pow", "handle_gfpoly_sqrt", "gfpoly_diff", "gfpoly_makemonic", "handle_gfpoly_gcd", "padding_oracle", "gfpoly_pow", "gfpoly_factor_sff", "gfpoly_factor_ddf", "gfpoly_factor_edf"}:
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
                self.results["responses"][test_case_id] = result
        
        # Process sequential cases
        for test_case, test_case_id in sequential_cases:
            test_case_id, result = process_test_case(test_case, test_case_id)
            self.results["responses"][test_case_id] = result


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

