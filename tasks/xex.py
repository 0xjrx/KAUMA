#!/usr/bin/env python3
import base64
from tasks.gfmul import gfmul
from tasks.sea import sea_enc, sea_dec

class XEX:
    """
    This class can encrypt and decrypt blocks using XEX as in full disk encryption
    using input in base64.

    The class function xex_round_* takes a key, tweak and input, beeing either ciphertext oder plaintext
    which can be a multiple of 16 Byte and is encoded in base64. When creating an instance of this class
    the input is automatically sliced into 16 Byte blocks, while the Key, which is 32 bytes long, is split into two parts.
    Afterwards, if the class function is called, both keys are used to iteratively encrypt the plaintext blocks
    or decrypt the ciphertext.
    
    Args:
        key = Key for en/decryption, length 32 Bytes
        tweak = Used for multiplication with alpha and xor with the input
        input  = this can eithe be the plaintext or ciphertext, encoded in b64 as an integer multiple of at least 16 Byte
    
    Returns:
        Encrypted ciphertext or decrypted plaintext in both base64 encoding

    Notes:
        As of now the alpha polynomial for multiplication is hardcoded, this can be subject to change

    """
    def __init__(self, key, tweak, input):
        self.key = self._handle_key(key)
        self.tweak = tweak
        self.input = self._slice_input(input)
   
    # For our input to be directly split as of creating an instance of this class we implement
    # a helper function that splits the key
    def _handle_key(self, key) -> list:
        bytes = base64.b64decode(key)
        key_1 = bytes[:-16]
        key_2 = bytes[16:]
        return [base64.b64encode(key_1).decode('utf-8'), base64.b64encode(key_2).decode('utf-8')]
    
    # For our input to be sliced into the correct blocks we use this helper function
    # that is called as of creating an instance of XEX
    def _slice_input(self, input) -> list:
        bytes = base64.b64decode(input)
        input_block = []
        for i in range (0, len(bytes), 16):        
            input_block.append(base64.b64encode(bytes[i:i + 16]).decode('utf-8'))
        return input_block

    # We need to encrypt the tweak once per encryption/decryption. This function is called 
    # at the beginning of every encryption
    def _tweak_encr(self) -> str:
        result = sea_enc(self.key[1], self.tweak)
        return result

    # This function encrypts an input and returns the ciphertext as base64
    def xex_round_enc(self)-> str:
        # Encrypt tweak outside loop
        tweak = self._tweak_encr()
        
        # We set our alpha polynomial
        alpha = "Ag=="

        # We initialize our result bytearray
        ciphertext = bytearray()

        # start loop for every block in input
        for input_block in self.input:
            
            # XOR Input 1 with tweak
            enc_tweak_bytes = base64.b64decode(tweak)
            input_bytes = base64.b64decode(input_block)
            xor_result = bytes(a ^ b for a, b in zip(enc_tweak_bytes, input_bytes))
            
            # Use sea128 to encryt result of encrypted tweak xor input 1
            encrypt_sea = sea_enc(self.key[0],base64.b64encode(xor_result).decode('utf-8'))       
            
            # xor encrypted tweak with result of sea128 -> Ciphertext
            encrypt_sea_bytes = base64.b64decode(encrypt_sea)
            xor_result2 = bytes(a ^ b for a, b in zip(enc_tweak_bytes, encrypt_sea_bytes))
            ciphertext.extend(xor_result2) 
            
            # Multiply tweak 
            tweak = gfmul(tweak,alpha) 
        return base64.b64encode(ciphertext).decode('utf-8')    
    
    def xex_round_dec(self) -> str:
        tweak = self._tweak_encr()
        alpha = "Ag=="
        ciphertext = bytearray()
        
        for input_block in self.input:
            
            enc_tweak_bytes = base64.b64decode(tweak)
            input_bytes = base64.b64decode(input_block)
            xor_result = bytes(a ^ b for a, b in zip(enc_tweak_bytes, input_bytes))
            
            decrypt_sea = sea_dec(self.key[0],base64.b64encode(xor_result).decode('utf-8'))       
            
            encrypt_sea_bytes = base64.b64decode(decrypt_sea)
            
            xor_result2 = bytes(a ^ b for a, b in zip(enc_tweak_bytes, encrypt_sea_bytes))
            ciphertext.extend(xor_result2) 
            
            tweak = gfmul(tweak,alpha) 
        return base64.b64encode(ciphertext).decode('utf-8')    

    




