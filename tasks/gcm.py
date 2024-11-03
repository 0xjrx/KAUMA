#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tasks.sea import sea_enc

# Helper function that reverses the bits of a given byte
# this is needed as gcm uses a different semantic when performing galois field operations
def reverse_bit(byte):
    result = 0
    for _ in range(8):
        result = (result << 1) | (byte & 1)
        byte >>= 1
    return result

# Class representing  elements in the Galois Field GF(2^128) 
# Using this class one can easily multiply and add field elements using normal
# operators like '+' or '*'
class FieldElementGCM:
    def __init__(self, element):
        self.element = element
    
    # Semantic transformation of a field element used for the Galois field multiplication
    # Performs bit reversal ob the individual bytes of a Field Element
    def _gcm_sem(self, element):
        # Padd the the base64 string if necessary
        while len(element) % 4 != 0:
            element += '='
        elem_bytes = base64.b64decode(element)
        byte_list = []
        
        for i in range(len(elem_bytes)):
            byte_list.append(elem_bytes[i])
        # Reverse bits in each byte
        reversed_bytes = [reverse_bit(byte) for byte in byte_list]
    
        reversed_bytes_arr = bytes(reversed_bytes)
        return base64.b64encode(reversed_bytes_arr).decode('utf-8')
    
    # Multiplication operation in GF(2^128)
    # Implements a carryless multiplication algorithm withm modular reduction based on 
    # russian peasant multiplication

    def __mul__(self, other):
        # irreducible polynomial for GF(2^128)
        IRR_POLY = "hwAAAAAAAAAAAAAAAAAAAAE="
    
        # To be able to easily work with these values and do such things as bit shifts
        # we need to convert the base64 string to its byte representation and then into an integer
        
        first = base64.b64decode(self._gcm_sem(self.element))
        multiplicant = int.from_bytes(first, byteorder = 'little')
        
        second = base64.b64decode(other._gcm_sem(other.element))
        multiplier = int.from_bytes(second, byteorder = 'little')
        
        # We also need to decode the irreducible polynomial as its needed for reduction
        poly_bytes = base64.b64decode(IRR_POLY)
        reduction_polynomial = int.from_bytes(poly_bytes, byteorder = 'little')

        # We initialize our result
        product = 0

        # We handle the first bit of the loop outside
        if multiplier & 1:
            product^=multiplicant
        multiplier>>=1

        # Main multiplication loop
        for _ in range((len(second)*8)-1):    
            # Left shift as equivalent of multiplication by x
            multiplicant<<=1

            # Reduction of the polynomial if it becomes too large
            if multiplicant.bit_length()>=129:
                multiplicant ^= reduction_polynomial
        
            # Add to result if the corresponding bit in second element is 1 
            if multiplier & 1:
                product ^= multiplicant
            
            # Right shift to process next bit
            multiplier >>= 1
        
        # Convert the result back to base64
        product_bytes = product.to_bytes(16, byteorder = 'little')
        encoded_product = base64.b64encode(product_bytes).decode('utf-8')
        gcm_encoded_product = self._gcm_sem(encoded_product)
        return FieldElementGCM(gcm_encoded_product)
    
    # Addition operation for field elements in GF(2^128)
    # Per definition the addition of field elements is xor
    def __add__(self, other):
        first = base64.b64decode(self.element)
        second = base64.b64decode(other.element)
        xor = bytes(a^b for a,b in zip(first, second))
        return FieldElementGCM(base64.b64encode(xor).decode('utf-8'))

    
# Helper function to slice a input of variable length into 16 byte blocks
def _slice_input(input) -> list:
    bytes = base64.b64decode(input)
    input_block = []
    for i in range (0, len(bytes), 16):        
        input_block.append(bytes[i:i + 16])
    return input_block
# Main  GCM encryption function    
def GCM_encrypt(nonce, key, plaintext, associated_data):
    # Split the plaintext into blocks
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    
    # Generate the authentication key H
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    null_array = bytes(16)
    auth_key = encryptor.update(null_array) + encryptor.finalize()
    #print(f"Auth Key: {base64.b64encode(auth_key).decode('utf-8')}") 
    
    # Calculate the associated data length in bits, needef for the length field L
    len_a = len(associated_data_bytes) * 8

    # Pad associated data before ghash if necessary
    if len(associated_data_bytes) <= 128:
        padding = 16 - len(associated_data_bytes)
        associated_data_bytes = associated_data_bytes + b'\x00' * padding
    
    # Initial GHASH with the associated data
    associated_data_bytes_fe = FieldElementGCM(base64.b64encode(associated_data_bytes).decode('utf-8'))
    null_array_fe = FieldElementGCM(base64.b64encode(null_array).decode('utf-8'))
    ghash_1 = associated_data_bytes_fe + null_array_fe        
    h_field_elem = FieldElementGCM(base64.b64encode(auth_key).decode('utf-8'))
    ghash_first = ghash_1 * h_field_elem
        
    # Encrypt plaintext blocks using a counter
    for block in plaintext_blocks:
        # Counter starts at 2 (1 is reserved for tag)
        ctr = 2
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        
        # XOR with plaintext and update GHASH
        ct = bytes(a ^ b for a, b in zip(encrypted_Y, block))
        ghash_ct = FieldElementGCM(base64.b64encode(ct).decode('utf-8'))
        xor_res = ghash_ct + ghash_first 
        mul_res = xor_res * h_field_elem
        ghash_first = mul_res
        
        ciphertext.extend(ct)
        ctr += 1
    
    # Prepare length block for GHASH finalization
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    #print(f"L is: {base64.b64encode(L).decode('utf-8')}")

    # Complete GHASH computation
    l_fe = FieldElementGCM(base64.b64encode(L).decode('utf-8'))
    ghash_res_1 = ghash_first + l_fe
    ghash_res = ghash_res_1 * h_field_elem
    
    # Generate Authentication Tag
    ctr_tag = 1
    ctr_tag_bytes = ctr_tag.to_bytes(4, 'big')
    y_0 = nonce_bytes + ctr_tag_bytes
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    tag_bytes = encryptor.update(y_0) + encryptor.finalize()
    tag_b64 = FieldElementGCM(base64.b64encode(tag_bytes).decode('utf-8'))
    tag = (tag_b64 + ghash_res).element
    #print(f"The Tag is: {tag}")
    
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":tag,"L":l_fe.element,"H":h_field_elem.element}
    
def GCM_encrypt_sea(nonce, key, plaintext, associated_data):
    # Split the plaintext into blocks
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    
    # Generate the authentication key H
    null_array = bytes(16)
    auth_key = sea_enc(key, base64.b64encode(null_array).decode('utf-8'))    #print(f"Auth Key: {base64.b64encode(auth_key).decode('utf-8')}") 
    
    # Calculate the associated data length in bits, needef for the length field L
    len_a = len(associated_data_bytes) * 8

    # Pad associated data before ghash if necessary
    if len(associated_data_bytes) <= 128:
        padding = 16 - len(associated_data_bytes)
        associated_data_bytes = associated_data_bytes + b'\x00' * padding
    
    # Initial GHASH with the associated data
    associated_data_bytes_fe = FieldElementGCM(base64.b64encode(associated_data_bytes).decode('utf-8'))
    null_array_fe = FieldElementGCM(base64.b64encode(null_array).decode('utf-8'))
    ghash_1 = associated_data_bytes_fe + null_array_fe        
    h_field_elem = FieldElementGCM(auth_key)
    ghash_first = ghash_1 * h_field_elem
        
    # Encrypt plaintext blocks using a counter
    for block in plaintext_blocks:
        # Counter starts at 2 (1 is reserved for tag)
        ctr = 2
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
        # XOR with plaintext and update GHASH
        ct = bytes(a ^ b for a, b in zip(base64.b64decode(encrypted_Y), block))
        ghash_ct = FieldElementGCM(base64.b64encode(ct).decode('utf-8'))
        xor_res = ghash_ct + ghash_first 
        mul_res = xor_res * h_field_elem
        ghash_first = mul_res
        
        ciphertext.extend(ct)
        ctr += 1
    
    # Prepare length block for GHASH finalization
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    #print(f"L is: {base64.b64encode(L).decode('utf-8')}")

    # Complete GHASH computation
    l_fe = FieldElementGCM(base64.b64encode(L).decode('utf-8'))
    ghash_res_1 = ghash_first + l_fe
    ghash_res = ghash_res_1 * h_field_elem
    
    # Generate Authentication Tag
    ctr_tag = 1
    ctr_tag_bytes = ctr_tag.to_bytes(4, 'big')
    y_0_bytes = nonce_bytes + ctr_tag_bytes
    y_0 = sea_enc(key, base64.b64encode(y_0_bytes).decode('utf-8'))
    tag_b64 = FieldElementGCM(y_0)
    tag = (tag_b64 + ghash_res).element
    #print(f"The Tag is: {tag}")
    
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":tag,"L":l_fe.element,"H":h_field_elem.element}


# Test inputs   
#nonce = "4gF+BtR3ku/PUQci"
#key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
#plaintext = "RGFzIGlzdCBlaW4gVGVzdA=="
#associated_data = "QUQtRGF0ZW4="


#print(GCM_encrypt_sea(nonce, key, plaintext, associated_data))
