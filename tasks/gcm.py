#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tasks.sea import sea_enc
from tasks.polynom import FieldElement

"""
Galois Counter Mode (GCM) Encryption implementation

This module implements the GCM encryption, providing confidentiality and authenticity.
GCM combines the counter mode with Galois Field multiplication for authentication and generates a tag.

The implementation includes both standard AES-GCM and a variant using SEA (Simple Encryption Algorithm),
as the underlying block cipher.

Key components:
- Field Arithmetics in GF(2^128) using FieldElementGCM class 
- GHASH authentication
- Counter mode encryption
- Tag generation
"""


 

def _slice_input(input) -> list:
    """
    Slice input data into 16-byte blocks for cipher operation.

    Args:
        input: Base64 encoded input
    
    Returns:
        List of 16-byte blocks
    """
    bytes = base64.b64decode(input)
    input_block = []
    for i in range (0, len(bytes), 16):        
        input_block.append(bytes[i:i + 16])
    return input_block

def ghash_associated_data(associated_data_blocks, h_field_elem):
    """
    Calculate GHASH for associated data (authenticated but not encrypted data).
    
    Args:
        associated_data_block: List of data blocks to authenticate
        h_field_elem: Authentication key H as a field element

    Returns:
        FieldElementGCM representing the initial GHASH value
    """
    bytes = bytearray(16)
    ghash_result = FieldElement(int.from_bytes(bytes, 'little'))
    for block in associated_data_blocks:
        if len(block) < 16:  # Pad last block if necessary
            block = block + b'\x00' * (16 - len(block))
        block_fe = FieldElement(int.from_bytes(block, 'little') )
        ghash_result = (ghash_result + block_fe) * h_field_elem
    return ghash_result


def GCM_encrypt(nonce, key, plaintext, associated_data):
    """
    Perform GCM encryption using AES as the underlying block cipher.

    Args:
        nonce: Base64 encoded nonce (should be kept unique for each encryption)
        key: Base64 encoded key
        plaintext: Base64 encoded data to encrypt
        associated_data: Base64 encoded data to authenticate but not encrypt

    Returns:
        Dictionary containing ciphertext, authentication tag, length field and Authentication Key H
    """
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    
    # Generate the authentication key H = AES_K(0)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    null_array = bytes(16)
    auth_key = encryptor.update(null_array) + encryptor.finalize()
    h_field_elem = FieldElement(int.from_bytes(auth_key, 'little'))
   
    # Process associated data
    associated_data_blocks = []
    for i in range(0, len(associated_data_bytes), 16):
        block = associated_data_bytes[i:i + 16]
        associated_data_blocks.append(block)
    
    # Initial GHASH calculation with the associated data
    ghash_result = ghash_associated_data(associated_data_blocks, h_field_elem)

    # Encrypt using counter mode starting at 2 (1 is reserved for tag)
    ctr = 2
    ghash_blocks = []
    for block in plaintext_blocks:
        
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        
        # XOR with plaintext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y[:len(block)], block))
        ciphertext.extend(ct)
        
        # Pad ciphertext for ghash if necessary
        if len(ct) < 16:
            ct = ct + b'\x00' * (16 - len(ct))
        ghash_blocks.append(ct)
        ctr += 1
    # Update and calculate GHASH
    for ct_block in ghash_blocks:
        ct_fe = FieldElement(int.from_bytes(ct_block, 'little'))
        ghash_result =(ghash_result + ct_fe) * h_field_elem

    # Add length block to GHASH
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    #print(base64.b64encode(L).decode())
    l_fe = FieldElement(int.from_bytes(L, 'little'))
    ghash_result = (ghash_result + l_fe)* h_field_elem   

    # Generate Authentication Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    tag_bytes = encryptor.update(y_0) + encryptor.finalize()
    tag_b64 = FieldElement(int.from_bytes(tag_bytes, 'little'))
    tag = (tag_b64 + ghash_result)
    
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":base64.b64encode(int.to_bytes(tag.element,16, 'little')).decode(),"L":base64.b64encode(int.to_bytes(l_fe.element,16, 'little')).decode(),"H":base64.b64encode(int.to_bytes(h_field_elem.element,16, 'little')).decode()}

def GCM_encrypt_sea(nonce, key, plaintext, associated_data):
    """
    Perform GCM Encryption using SEA (Simple Encryption Algorithm) as the block cipher.

    Implementation follows the same structure as standard GCM but uses SEA128
    instead of AES128 for encryption.

    Args and return match those of GCM_encrypt().
    """
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    
    # Generate H using SEA128
    null_array = bytes(16)
    h = sea_enc(key, base64.b64encode(null_array).decode('utf-8'))
    h_field_elem = FieldElement(int.from_bytes(base64.b64decode(h), 'little'))
   
    # Process associated data
    associated_data_blocks = []
    for i in range(0, len(associated_data_bytes), 16):
        block = associated_data_bytes[i:i + 16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        associated_data_blocks.append(block)
    
    
    ghash_result = ghash_associated_data(associated_data_blocks, h_field_elem) 
    
    # encrypt using counter initialized at 2
    ctr = 2
    ghash_blocks = []
    for block in plaintext_blocks:
        
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
        encrypted_Y_bytes = base64.b64decode(encrypted_Y)
        
        ct = bytes(a ^ b for a, b in zip(encrypted_Y_bytes[:len(block)], block))
        ciphertext.extend(ct)

        if len(ct) < 16:
            ct = ct + b'\x00' * (16 - len(ct))
        ghash_blocks.append(ct)
        ctr += 1
    
    # Update GHASH with ciphertext
    for ct_block in ghash_blocks:
        ct_fe = FieldElement(int.from_bytes(ct_block, 'little'))
        ghash_result =(ghash_result + ct_fe) * h_field_elem
    
    # Add length block
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    l_fe = FieldElement(int.from_bytes(L, 'little'))
    ghash_result = (ghash_result + l_fe)* h_field_elem   
    
    # Generate Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    y_0_enc = sea_enc(key, base64.b64encode(y_0).decode('utf-8'))
    tag_fe = FieldElement(int.from_bytes(base64.b64decode(y_0_enc), 'little'))
    tag = (tag_fe + ghash_result)

    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":base64.b64encode(int.to_bytes(tag.element,16, 'little')).decode(),"L":base64.b64encode(int.to_bytes(l_fe.element,16, 'little')).decode(),"H":base64.b64encode(int.to_bytes(h_field_elem.element,16, 'little')).decode()}

def GCM_decrypt(nonce, key, ciphertext, associated_data, tag):
    """
    Decrypt GCM ciphertext and verify the authentication tag using AES.

    Args:
        nonce: Base64 encoded nonce (must match encryption nonce)
        key: Base64 encoded encryption key
        ciphertext: Base64 encoded ciphertext to decrypt
        associated_data: Base64 encoded authenticated data
        tag: Authentication tag to verify
        
    Returns:
        Dictionary containing authentication status and decrypted plaintext    
    """
    ciphertext_blocks = _slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2

    # Decrypt ciphertext using a counter
    for block in ciphertext_blocks:
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        
        # XOR with ciphertext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y, block))
        
        plaintext.extend(ct)
        ctr += 1
    
    # Check authenticity of tag
    computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data)
    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}

    else:
        return {"authentic":False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}

def GCM_decrypt_sea(nonce, key, ciphertext, associated_data, tag):
    """
    Decrypt GCM ciphertext and authenticate using SEA.

    Args and Returns match those of GCM_decrypt().
    """
    ciphertext_blocks = _slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2
    # Encrypt plaintext blocks using a counter
    for block in ciphertext_blocks:
       
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
        # XOR with plaintext and update GHASH
        ct = bytes(a ^ b for a, b in zip(base64.b64decode(encrypted_Y), block))
        
        plaintext.extend(ct)
        ctr += 1

    # Check authenticity
    computed_tag =  GCM_encrypt_sea(nonce, key, base64.b64encode(plaintext), associated_data)
    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}
    else:
        return {"authentic": False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}
