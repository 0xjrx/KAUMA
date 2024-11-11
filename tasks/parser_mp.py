#!/usr/bin/env python3

import json
from tasks.poly import block2poly, poly2block, block2poly_gcm, poly2block_gcm
from common.common import stderr_write
import multiprocessing as mp
from tasks.gfmul import gfmul
from tasks.sea import sea_enc, sea_dec
from tasks.xex import XEX
from tasks.gcm import FieldElementGCM, GCM_encrypt, GCM_encrypt_sea, GCM_decrypt, GCM_decrypt_sea
from tasks.padding_oracle_crack import padding_oracle_crack
import time, base64

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
            case _:
                stderr_write(f"Unknown error for {action} with ID:{test_case_id}")
        return test_case_id, result
    
    except Exception as e:
        stderr_write(f"Error processing test case {test_case_id}: {str(e)}")
        return test_case_id, {"error": str(e)}
    
def handle_p2b(arguments):
    if arguments["semantic"] == "xex":
        coefficients = arguments["coefficients"]
        p2b = poly2block(coefficients)
        block = p2b.p2b()
        return {"block": block}
    if arguments["semantic"] == "gcm":
        coefficients = arguments["coefficients"]
        block = poly2block_gcm(coefficients)
        return {"block": block}

def handle_b2p(arguments):
    if arguments["semantic"] == "xex":
        block = arguments["block"]
        b2p = block2poly(block)
        poly = b2p.b2p()
        return {"coefficients":list(poly)}
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
        a_fe = FieldElementGCM(a)
        b_fe = FieldElementGCM(b)
        res = (a_fe*b_fe).element
        return {"product":res}
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
        return GCM_encrypt(nonce, key, plaintext, associated_data)
    if arguments["algorithm"] == 'sea128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        plaintext = arguments["plaintext"]
        associated_data = arguments["ad"]
        return GCM_encrypt_sea(nonce, key, plaintext, associated_data)
def handle_gcm_decrypt(arguments):
    if arguments["algorithm"] == 'aes128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        ciphertext = arguments["ciphertext"]
        associated_data = arguments["ad"]
        tag = arguments["tag"]
        return GCM_decrypt(nonce, key, ciphertext, associated_data, tag)
    if arguments["algorithm"] == 'sea128':
        nonce = arguments["nonce"]
        key = arguments["key"]
        ciphertext = arguments["ciphertext"]
        associated_data = arguments["ad"]
        tag = arguments["tag"]
        return GCM_decrypt_sea(nonce, key, ciphertext, associated_data, tag) 
def handle_po(arguments):
    hostname = arguments["hostname"]
    print(f"Hostname: {hostname}")
    port = arguments["port"]
    iv = base64.b64decode(arguments["iv"])
    ct = base64.b64decode(arguments["ciphertext"])
    result = padding_oracle_crack(hostname, port, iv, ct)
    return {"plaintext": result}

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
                if len(data["testcases"]) < 50:
                    processing_method = "sequential"
                    self._parse_sequential(data)
                else:
                    processing_method = "parallel"
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
    
    def _parse_sequential(self, data):
        stderr_write("Used sequential processing")
        for test_case_id, test_case in data["testcases"].items():
            test_case_id, result = process_test_case(test_case, test_case_id)
            self.results["responses"][test_case_id] = result
    
    def _parse_parallel(self, data):
        stderr_write("Used parallel processing")
        # Create workers
        num_cores = mp.cpu_count()
        pool = mp.Pool(processes=num_cores)
        # Process test cases in parallel
        test_cases = [
                (test_case, test_case_id)
                for test_case_id, test_case in data["testcases"].items()
                ]
        # Map processing functions to all test cases
        results = pool.starmap(
            process_test_case,
            test_cases
                )
                
        # Closse pool and wait for process completion
        pool.close()
        pool.join()
        # Collect all results
        for test_case_id, result in results:
            self.results["responses"][test_case_id] = result            


