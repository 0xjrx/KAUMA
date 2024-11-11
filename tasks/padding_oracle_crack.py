
#!/usr/bin/env python3
import base64
import socket
import struct
def slice_blocks_16(data):
    return [data[i:i + 16] for i in range(0, len(data), 16)]
def p16(val):
    return struct.pack('<H', val)
def padding_oracle_crack(host, port, iv, ciphertext):
    """
    Perform paddin oracle attack to decrypt a ciphertext

    Args:
        host: IP address of the oracle server
        port: port number for the server
        iv  : Initial vector used for encryption
        ciphertext: The encrypted ciphertext to be decrypted

    Returns:
        bytes: The decrypted plaintext.
    """
    plaintext = bytearray()  
    ciphertext_blocks = slice_blocks_16(ciphertext)
    ct = 0 
    for block in ciphertext_blocks:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        intermediate = bytearray([0]*16)
        current_plaintext = bytearray([0]*16)  
        #stderr_write(f"Connected to {host}:{port}")
        s.connect((host, port))
            
        counter = 256
        s.sendall(block)
   
        # Iterate through the ciphertext block from right to left
        for i in range(15, -1, -1):
            padding_value = 16-i
            candidates = []
            
            if i == 15:
                q_block = bytearray([0]*16)
                block = b''
                length = p16(256)
                block += length


                for guess in range(0,256):
                    q_block[i] = guess
                    block += q_block
                s.sendall(block)

                response = s.recv(256)
                candidates = [] 
                #print(f"Response: {response}")
                for j in range(0,256):
                    if response[j] == 1:
                        candidates.append(j)
                #print(f"Candidates: {candidates}")
                
                true_candidate = None
                for candidate in candidates:
                    s.sendall(p16(1))
                    verify_block = bytearray([0]*16)
                    verify_block[15] = candidate
                    verify_block[14] = candidate ^ 0xFF
                    s.sendall(verify_block)
                    
                    verif_response = s.recv(1)
                    if verif_response == b"\x01":
                        true_candidate = candidates[0]
                    else:
                        true_candidate = candidates[1]

                if true_candidate is not None:
                    intermediate[15] = true_candidate ^ padding_value
                    if ct == 0:
                        current_plaintext[15] = intermediate[15] ^ iv[15]
                    else:
                        current_plaintext[15] = intermediate[15] ^ ciphertext_blocks[ct-1][15]
                else:
                    break
            
            else:
                q_block = bytearray([0]*16)
                
                for g in range(i+1, 16):
                    q_block[g] = intermediate[g] ^ padding_value 
                
                block = b''
                length = p16(256)
                block += length
                for guess in range(0,256):
                    q_block[i] = guess
                    block+=q_block
                s.sendall(block)
                
                valid = None
                response_else = s.recv(256)
                for e in range(0,256):
                    if response_else[e] == 1:
                        valid = e
                        q_block[i] = valid
                        break
                        
                if valid is not None:
                    intermediate[i] = valid ^ padding_value
                    if ct == 0:
                        current_plaintext[i] = intermediate[i] ^ iv[i]
                    else:
                        current_plaintext[i] = intermediate[i] ^ ciphertext_blocks[ct-1][i]
                else:
                    break

        # After processing the entire block, extend plaintext
        plaintext.extend(current_plaintext)
        s.close()
        ct += 1 
        
    return plaintext

ct = base64.b64decode("RWNwJGx1cyhsY2VpLWVgYjYEGFRJFhpUFgoGCVUOHAFSam81bF58P3dyZGYwdBETQ3h8IXlIayduaH96LWoOEw==")
iv = base64.b64decode("dxTwbO/hhIeycOTbTnp8QQ==")    
port = 42069
host = '127.0.0.1'
print("Starting padding oracle attack...")
plaintext = padding_oracle_crack(host, port,iv, ct)
print(f"Final plaintext:  {plaintext}")

