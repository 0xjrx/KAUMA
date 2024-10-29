#!/usr/bin/env python3
import base64
from tasks.gfmul import gfmul
from tasks.sea import sea_enc, sea_dec

key = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
tweak = "6VXORr+YYHrd2nVe0OlA+Q=="
input =       "/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW"
key2 = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
ciphertext =  "lr/ItaYGFXCtHhdPndE65yg7u/GIdM9wscABiiFOUH2Sbyc2UFMlIRSMnZrYCW1a"

class XEX:
    def __init__(self, key, tweak, input):
        self.key = self._handle_key(key)
        self.tweak = tweak
        self.input = self._slice_input(input)
    
    def _base64_to_int(self, b64) -> int:
        bytes = base64.b64decode(b64)
        return int.from_bytes(bytes, 'big')
    
    def _handle_key(self, key):
        bytes = base64.b64decode(key)
        key_1 = bytes[:-16]
        key_2 = bytes[16:]
        return [base64.b64encode(key_1).decode('utf-8'), base64.b64encode(key_2).decode('utf-8')]
    
    def _slice_input(self, input) -> list:
        bytes = base64.b64decode(input)
        input_block = []
        for i in range (0, len(bytes), 16):        
            input_block.append(base64.b64encode(bytes[i:i + 16]).decode('utf-8'))
        return input_block


    def _tweak_encr(self):
        result = sea_enc(self.key[1], self.tweak)
        return result
    
    def xex_round_enc(self):
        # Encrypt tweak outside loop
        tweak = self._tweak_encr()
        alpha = "Ag=="
        ciphertext = bytearray()
        # start loop for every element in input
        for input_block in self.input:
            # XOR Input 1 with tweak
            enc_tweak_bytes = base64.b64decode(tweak)
            input_bytes = base64.b64decode(input_block)
            xor_result = bytes(a ^ b for a, b in zip(enc_tweak_bytes, input_bytes))
            
            # Use sea128 to encryt result of encrypted tweak xor input 1
            encrypt_sea = sea_enc(self.key[0],base64.b64encode(xor_result).decode('utf-8'))       
            
            # xor encrypted tweak with res of sea128 -> Ciphertext
            encrypt_sea_bytes = base64.b64decode(encrypt_sea)
            xor_result2 = bytes(a ^ b for a, b in zip(enc_tweak_bytes, encrypt_sea_bytes))
            ciphertext.extend(xor_result2) 
            # Multiply tweak 
            tweak = gfmul(tweak,alpha) 
        return base64.b64encode(ciphertext).decode('utf-8')    
    
    def xex_round_dec(self):
        # Encrypt tweak outside loop
        tweak = self._tweak_encr()
        alpha = "Ag=="
        ciphertext = bytearray()
        # start loop for every element in input
        for input_block in self.input:
            # XOR Input 1 with tweak
            enc_tweak_bytes = base64.b64decode(tweak)
            input_bytes = base64.b64decode(input_block)
            xor_result = bytes(a ^ b for a, b in zip(enc_tweak_bytes, input_bytes))
            
            decrypt_sea = sea_dec(self.key[0],base64.b64encode(xor_result).decode('utf-8'))       
            
            encrypt_sea_bytes = base64.b64decode(decrypt_sea)
            
            xor_result2 = bytes(a ^ b for a, b in zip(enc_tweak_bytes, encrypt_sea_bytes))
            ciphertext.extend(xor_result2) 
            
            # Multiply tweak 
            tweak = gfmul(tweak,alpha) 
        return base64.b64encode(ciphertext).decode('utf-8')    

    




