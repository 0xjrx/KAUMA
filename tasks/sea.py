
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sea_key = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11




def sea_enc(key: str, input: str) -> str:
    """
    These functions en/decrypt a given 16 byte input encoded in base64 using a modified version of aes ecb.
    The modification itself is just an xor of the result of aes de/encryption with a given vector.

    Args:
        key: Key for de/encryption, 16 Bytes, ecoded in base64
        input: Input block, either plaintext or ciphertext, encoded in b64 and 16 bytes long

    Notes:
        The vector or sea_key used for xor is hardcoded in this example

    """

    # Decode the key and input
    key_byte_arr = base64.b64decode(key)
    input_byte_arr = base64.b64decode(input)
    
    # Construct the Cipher instance with mode AES ECB
    cipher = Cipher(algorithms.AES(key_byte_arr), modes.ECB())
    
    # Set the encryption function
    encryptor = cipher.encryptor()
    
    # Encrypt our input
    ciphertext = encryptor.update(input_byte_arr) + encryptor.finalize()
    
    # Retransform the ciphertext to int, xor with the sea_key and reencode our result
    ct_int = int.from_bytes(ciphertext, 'big')
    result = base64.b64encode((ct_int^sea_key).to_bytes(16,'big')).decode('utf-8')
    return(result)

def sea_dec(key: str, input: str):
    key_byte_arr = base64.b64decode(key)
    input_byte_arr = base64.b64decode(input)
    
    input_int = int.from_bytes(input_byte_arr, 'big')
    ct = (input_int ^ sea_key).to_bytes(16, 'big')
    
    cipher = Cipher(algorithms.AES(key_byte_arr), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ct)+decryptor.finalize()
    
    return(base64.b64encode(plaintext).decode('utf-8'))
    
    


