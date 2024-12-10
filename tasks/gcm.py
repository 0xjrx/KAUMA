#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tasks.sea import sea_enc
from common import gcm_sem, slice_input, calc_l, pad_slice_ct, pad_ad
from tasks.polynom_perf import FieldElement


"""
Galois Counter Mode (GCM) Encryption implementation

This module implements the GCM encryption, providing confidentiality and authenticity.
GCM combines the counter mode with Galois Field multiplication for authentication and generates a tag.

The implementation includes both standard AES-GCM and a variant using SEA (Simple Encryption Algorithm),
as the underlying block cipher.

Key components:
- Field Arithmetics in GF(2^128) using FieldElement class 
- GHASH authentication
- Counter mode encryption
- Tag generation
"""


 
def ghash(associated_data_blocks, h, l,ct_blocks):
    """
    Calculate GHASH for aes_gcm
    """
    h = FieldElement(gcm_sem(h.element))
    l = FieldElement(gcm_sem(l.element))
    bytes = bytearray(16)
    ghash_result = FieldElement(int.from_bytes(bytes, 'little'))
    
    for block in associated_data_blocks:
        if len(block) < 16:  # Pad last block if necessary
            block = block + b'\x00' * (16 - len(block))
        
        block_fe = gcm_sem(int.from_bytes(block, 'little') )
        block_rev = FieldElement(block_fe)
        ghash_result = (ghash_result + block_rev) * h
    #print(f"Ghash res ad: {gcm_sem(ghash_result.element)}")
    
    for ct_block in ct_blocks:
        ct_fe = gcm_sem(int.from_bytes(ct_block, 'little'))
        ct_rev =  FieldElement(ct_fe)
        ghash_result = (ghash_result +ct_rev) * h 
    #print(f"ghash res CT: {gcm_sem(ghash_result.element)}") 
    ghash_result = (ghash_result + l) * h
    #print(f"Ghash res after add l: {gcm_sem(ghash_result.element)} ")
    return ghash_result


def GCM_encrypt(nonce, key, plaintext, associated_data, mode):
    """
    Perform GCM encryption using AES or SEA as the underlying block cipher.

    Args:
        nonce: Base64 encoded nonce (should be kept unique for each encryption)
        key: Base64 encoded key
        plaintext: Base64 encoded data to encrypt
        associated_data: Base64 encoded data to authenticate but not encrypt

    Returns:
        Dictionary containing ciphertext, authentication tag, length field and Authentication Key H
    """
    plaintext_blocks = slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    null_array = bytes(16)
    # Generate the authentication key H = AES_K(0)
    if mode =="aes":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        auth_key = encryptor.update(null_array) + encryptor.finalize()
    else:
        auth_key = base64.b64decode(sea_enc(key, base64.b64encode(null_array).decode('utf-8')))
    h_field_elem = FieldElement(int.from_bytes(auth_key, 'little'))
   
    # Process associated data
    associated_data_blocks = pad_ad(associated_data_bytes)
    
    # Encrypt using counter mode starting at 2 (1 is reserved for tag)
    ctr = 2
    ghash_blocks = []
    for block in plaintext_blocks:
        
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        if mode =="aes": 
            # Encrypt Y
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            encryptor = cipher.encryptor()
            encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        else:
             encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
             encrypted_Y = base64.b64decode(encrypted_Y)
        # XOR with plaintext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y[:len(block)], block))
        ciphertext.extend(ct)
        
        # Pad ciphertext for ghash if necessary
        if len(ct) < 16:
            ct = ct + b'\x00' * (16 - len(ct))
        ghash_blocks.append(ct)
        ctr += 1
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    l_fe = FieldElement(int.from_bytes(L, 'little'))
    #print(f"L_fe: {l_fe.element}")
    # Initial GHASH calculation with the associated data
    ghash_result = ghash(associated_data_blocks, h_field_elem,l_fe,ghash_blocks)

    # Generate Authentication Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    if mode == "aes":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        y_0_enc = encryptor.update(y_0) + encryptor.finalize()
    else:
        y_0_enc = base64.b64decode(sea_enc(key, base64.b64encode(y_0).decode()))
    
    tag_b64 = gcm_sem(int.from_bytes(y_0_enc, 'little'))
    tag_b64 = FieldElement(tag_b64)
    tag = (tag_b64 + ghash_result)
    tag = FieldElement(gcm_sem(tag.element)) 
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":base64.b64encode(int.to_bytes(tag.element,16, 'little')).decode(),"L":base64.b64encode(int.to_bytes(l_fe.element,16, 'little')).decode(),"H":base64.b64encode(int.to_bytes(h_field_elem.element,16, 'little')).decode()}

def GCM_decrypt(nonce, key, ciphertext, associated_data, tag, mode):
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
    ciphertext_blocks = slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2

    # Decrypt ciphertext using a counter
    for block in ciphertext_blocks:
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        if mode =="aes":
            # Encrypt Y
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            encryptor = cipher.encryptor()
            encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        else: 
            encrypted_Y = base64.b64decode(sea_enc(key, base64.b64encode(Y).decode('utf-8')))

        # XOR with ciphertext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y, block))
        
        plaintext.extend(ct)
        ctr += 1
    
    # Check authenticity of tag
    if mode =="aes":
        computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data, "aes")
    else:
        computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data, "sea")

    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}

    else:
        return {"authentic":False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}



