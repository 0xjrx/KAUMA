#!/usr/bin/env python3

#!/usr/bin/env python3

import json
from tasks.poly import block2poly, poly2block
from common.common import stderr_write
from tasks.gfmul import gfmul

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
                

    def handleb2p(self, arguments, test_case_id):
        if arguments["semantic"] == "xex":
            block = arguments["block"]
            b2p = block2poly(block)
            poly = b2p.b2p()
            self.results["responses"][test_case_id] = {"coefficients":list(poly)}
    def handle_gfmul(self, arguments, test_case_id):
        if arguments["semantic"] == 'xex':
            a = arguments["a"]
            b = arguments["b"]
            res = gfmul(a,b)
            self.results["responses"][test_case_id] = {"product":res}





