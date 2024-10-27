
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sea_key = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11




def sea_enc(key: str, input: str):
    key_byte_arr = base64.b64decode(key)
    input_byte_arr = base64.b64decode(input)
    cipher = Cipher(algorithms.AES(key_byte_arr), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(input_byte_arr) + encryptor.finalize()
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
    
    


