#!/usr/bin/env python3

import json
from tasks.poly import block2poly, poly2block, block2poly_gcm, poly2block_gcm
from common.common import stderr_write
from tasks.gfmul import gfmul
from tasks.sea import sea_enc, sea_dec
from tasks.xex import XEX
from tasks.gcm import FieldElementGCM, GCM_encrypt, GCM_encrypt_sea, GCM_decrypt, GCM_decrypt_sea 

class ParseJson:
    def __init__(self, filename):
        self.filename = filename
        self.results = {"responses":{}} 
    def parse(self):
        try:        
            with open(self.filename, 'r') as file:
                data = json.load(file)
                
                # We need to catch the UUID and test case dictionary
                for test_case_id, test_case in data["testcases"].items():
                    action = test_case.get("action")
                    arguments = test_case.get("arguments")
                    
                    
                    # We need to pass the dictionary to the different action handlers
                    match action:
                        case "poly2block":
                            self.handlep2b(arguments, test_case_id)
                        case "block2poly":
                            self.handleb2p(arguments, test_case_id)
                        case "gfmul":
                            self.handle_gfmul(arguments, test_case_id)
                        case "sea128":
                            self.handle_sea(arguments, test_case_id)
                        case "xex":
                            self.handle_xex(arguments, test_case_id)
                        case "gcm_encrypt":
                            self.handle_gcm_encrypt(arguments, test_case_id)
                        case "gcm_decrypt":
                            self.handle_gcm_decrypt(arguments, test_case_id)
                        case _:
                            stderr_write(f"Unknown error for {action} with ID:{test_case_id}")
                                   # For the testserver we need to throw the results in dict format to stdout
            print(json.dumps(self.results))
        
        # We need exception in case a key is not given    
        except KeyError as e:
            stderr_write(f"Missing key in given Testfile {e}")
        except json.JSONDecodeError:
            stderr_write("Error: Failed to decode the file given")
    

    def handlep2b(self, arguments, test_case_id):    
        # We need to check for the semantic
        if arguments["semantic"] == "xex":
            coefficients = arguments["coefficients"]
            p2b = poly2block(coefficients)
            block = p2b.p2b()
            # We need to pass the res to our own result dictionary
            self.results["responses"][test_case_id] = {"block":block}
        if arguments["semantic"] == "gcm":
            coefficients = arguments["coefficients"]
            block = poly2block_gcm(coefficients)
            self.results["responses"][test_case_id] = {"block":block}        
    def handleb2p(self, arguments, test_case_id):
        if arguments["semantic"] == "xex":
            block = arguments["block"]
            b2p = block2poly(block)
            poly = b2p.b2p()
            self.results["responses"][test_case_id] = {"coefficients":list(poly)}
        if arguments["semantic"] == "gcm":
            block = arguments["block"]
            poly = block2poly_gcm(block)
            self.results["responses"][test_case_id] = {"coefficients":poly}
    def handle_gfmul(self, arguments, test_case_id):
        if arguments["semantic"] == 'xex':
            a = arguments["a"]
            b = arguments["b"]
            res = gfmul(a,b)
            self.results["responses"][test_case_id] = {"product":res}
        if arguments["semantic"] == 'gcm':
            a = arguments["a"]
            b = arguments["b"]
            a_fe = FieldElementGCM(a)
            b_fe = FieldElementGCM(b)
            res = (a_fe*b_fe).element
            self.results["responses"][test_case_id] = {"product":res}

    def handle_sea(self, arguments, test_case_id):
        if arguments["mode"] =='encrypt':
            key = arguments["key"]
            input = arguments["input"]
            res = sea_enc(key, input)
            self.results["responses"][test_case_id] = {"output":res}
        if arguments["mode"] =='decrypt':
            key = arguments["key"]
            input = arguments["input"]
            res = sea_dec(key, input)
            self.results["responses"][test_case_id] = {"output":res}
    def handle_xex(self, arguments, test_case_id):
        if arguments["mode"] == 'encrypt':
            key = arguments["key"]
            tweak = arguments["tweak"]
            input = arguments["input"]
            xex_instance = XEX(key, tweak, input)
            res = xex_instance.xex_round_enc()
            self.results["responses"][test_case_id] = {"output": res}
        if arguments["mode"] == 'decrypt':
            key = arguments["key"]
            tweak = arguments["tweak"]
            input = arguments["input"]
            xex_instance = XEX(key, tweak, input)
            res = xex_instance.xex_round_dec()
            self.results["responses"][test_case_id] = {"output": res}
    def handle_gcm_encrypt(self, arguments, test_case_id):
        if arguments["algorithm"] == 'aes128':
            nonce = arguments["nonce"]
            key = arguments["key"]
            plaintext = arguments["plaintext"]
            associated_data = arguments["ad"]
            result = GCM_encrypt(nonce, key, plaintext, associated_data)
            self.results["responses"][test_case_id] = result
        if arguments["algorithm"] == 'sea128':
            nonce = arguments["nonce"]
            key = arguments["key"]
            plaintext = arguments["plaintext"]
            associated_data = arguments["ad"]
            result = GCM_encrypt_sea(nonce, key, plaintext, associated_data)
            self.results["responses"][test_case_id] = result
    def handle_gcm_decrypt(self, arguments, test_case_id):
        if arguments["algorithm"] == 'aes128':
            nonce = arguments["nonce"]
            key = arguments["key"]
            ciphertext = arguments["ciphertext"]
            associated_data = arguments["ad"]
            tag = arguments["tag"]
            result = GCM_decrypt(nonce, key, ciphertext, associated_data, tag)
            self.results["responses"][test_case_id] = result
        if arguments["algorithm"] == 'sea128':
            nonce = arguments["nonce"]
            key = arguments["key"]
            ciphertext = arguments["ciphertext"]
            associated_data = arguments["ad"]
            tag = arguments["tag"]
            result = GCM_decrypt_sea(nonce, key, ciphertext, associated_data, tag)
            self.results["responses"][test_case_id] = result
        
   





