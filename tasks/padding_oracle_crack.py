
#!/usr/bin/env python3
import base64
import socket
import struct
import time
def slice_blocks_16(data):
    return [data[i:i + 16] for i in range(0, len(data), 16)]
def p16(val):
    return struct.pack('<H', val)
def u16(val):
    return struct.unpack('<H', val)[0]
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
    plaintext = bytearray() # Initialize empty bytearray to store plaintext
    ciphertext_blocks = slice_blocks_16(ciphertext)
    ct = 0 # Track the current ciphertext block
    
    for block in ciphertext_blocks:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        intermediate = bytearray([0]*16)

        # Connect to the server
        print(f"Connected to {host}:{port}")
        s.connect((host, port))
        #s.setblocking(True)
            
        # Initialize q block with zeros
        q_block = bytearray([0]*16)
        counter = 256 # Maximum number of guesses
        s.sendall(block)
   
        # Send the current ciphertext block

        # Iterate through the ciphertext block from right to left
        for i in range(15, -1, -1):
            plaintext_byte = bytearray([0]*16)
            padding_value = 16-i
            candidates = []
            if i ==15:
                length = p16(counter)
                s.sendall(length)            

                for guess in range(0,256):
                    # Counter to length field and send
                    q_block[i] = guess

                    s.sendall(q_block)

                response = s.recv(256)
                for j in range(0,256):
                    if response[j] == b'\x01':
                        candidates.append(j)
                true_candidate = None
                for candidates in candidates:
                    s.sendall(block)
                    s.sendall(p16(1))
                    verify_block = bytearray([0]*16)
                    verify_block[15] = candidates
                    verify_block[14] = candidates ^ 0xFF
                    s.sendall(verify_block)
                    response = s.recv(1)
                    if response == b'x01':
                        true_candidate = candidates[0]
                        break
                    else:
                        true_candidate = candidates[1]
                        break
                if true_candidate:  
                    intermediate[15] = true_candidate ^ padding_value
                    
                plaintext_byte[15] = intermediate[15] ^ ciphertext_blocks[ct-1][15]
                    
                plaintext.append(plaintext_byte[15])
            
            else:
                length = p16(counter)
                s.sendall(length)

                for guess in range(0,256):
                    q_block[i] = guess
                    s.sendall(q_block)
                
                valid = None
                response = s.recv(256)
                for e in range(0,256):
                    if response[e] == b'\x01':
                        valid = e
                        q_block[i] = valid
                if valid is not None:
                    intermediate[i] = valid ^ padding_value
                    if ct ==0:
                        plaintext_byte[i] = intermediate[i] ^ iv[i]
                    else:
                        plaintext_byte[i] = intermediate ^ ciphertext_blocks[ct-1][i]
                plaintext.append(plaintext_byte[i])
        s.close()
        ct += 1 
    plaintext.reverse()
    print(base64.b64encode(plaintext).decode())
    return plaintext
# Main execution
ct = base64.b64decode("RWNwJGx1cyhsY2VpLWVgYjYEGFRJFhpUFgoGCVUOHAFSam81bF58P3dyZGYwdBETQ3h8IXlIayduaH96LWoOEw==")
iv = base64.b64decode("dxTwbO/hhIeycOTbTnp8QQ==")    
port = 42069
host = '127.0.0.1'
print("Starting padding oracle attack...")
plaintext = padding_oracle_crack(host, port,iv, ct)
print(f"Final plaintext:  {plaintext}")

