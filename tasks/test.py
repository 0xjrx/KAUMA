#!/usr/bin/env python3
import base64
import socket
import struct
from typing import List, Tuple, Optional

class PaddingOracleAttack:
    """Implementation of a padding oracle attack against CBC mode encryption."""
    
    def __init__(self, host: str, port: int):
        """Initialize the attack parameters.
        
        Args:
            host: Target host address
            port: Target port number
        """
        self.host = host
        self.port = port
        
    @staticmethod
    def slice_blocks_16(data: bytes) -> List[bytes]:
        """Split data into 16-byte blocks.
        
        Args:
            data: Input bytes to be split
            
        Returns:
            List of 16-byte blocks
        """
        return [data[i:i + 16] for i in range(0, len(data), 16)]
    
    def _try_padding(self, block: bytes, q_block: bytearray) -> Optional[int]:
        """Send a block to the oracle and check for valid padding.
        
        Args:
            block: The ciphertext block
            q_block: The query block being tested
            
        Returns:
            Index of valid padding byte if found, None otherwise
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.host, self.port))
                s.setblocking(True)
                
                # Send the block
                s.sendall(block)
                
                # Send length and query blocks
                length = len(q_block).to_bytes(2, 'little')
                s.sendall(length)
                s.sendall(bytes(q_block))
                
                # Receive and check padding
                pad_buf = s.recv(255)
                return next((index for index, r in enumerate(pad_buf) if r == 0x01), None)
                
            except socket.error as e:
                print(f"Socket error occurred: {e}")
                return None
    
    def decrypt_block(self, prev_block: bytes, curr_block: bytes) -> bytes:
        """Decrypt a single block using the padding oracle attack.
        
        Args:
            prev_block: Previous ciphertext block (or IV for first block)
            curr_block: Current ciphertext block to decrypt
            
        Returns:
            Decrypted plaintext block
        
        Raises:
            ValueError: If padding oracle attack fails
        """
        plaintext = bytearray()
        q_block = bytearray([0] * 16)
        
        # Work through each byte position
        for i in range(15, -1, -1):
            found_valid = False
            
            # Try all possible byte values
            for byte_val in range(256):
                q_block[i] = byte_val
                valid = self._try_padding(curr_block, q_block)
                
                if valid is not None:
                    found_valid = True
                    # Calculate plaintext byte using XOR
                    padding_value = 16 - i
                    intermediate = byte_val ^ padding_value
                    plaintext_byte = intermediate ^ prev_block[i]
                    plaintext.append(plaintext_byte)
                    
                    # Update padding for next round
                    next_padding = padding_value + 1
                    for pos in range(i, 16):
                        intermediate = q_block[pos] ^ padding_value
                        q_block[pos] = intermediate ^ next_padding
                    break
            
            if not found_valid:
                raise ValueError(f"Failed to find valid padding for position {i}")
                
        plaintext.reverse()
        return bytes(plaintext)
    
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt the entire ciphertext using padding oracle attack.
        
        Args:
            iv: Initialization vector
            ciphertext: Complete ciphertext to decrypt
            
        Returns:
            Decrypted plaintext
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
            
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
            
        blocks = self.slice_blocks_16(ciphertext)
        plaintext = bytearray()
        
        # Decrypt first block using IV
        print(f"Decrypting block 1/{len(blocks)}...")
        plaintext.extend(self.decrypt_block(iv, blocks[0]))
        
        # Decrypt remaining blocks
        for i in range(1, len(blocks)):
            print(f"Decrypting block {i+1}/{len(blocks)}...")
            plaintext.extend(self.decrypt_block(blocks[i-1], blocks[i]))
            
        return bytes(plaintext)

def main():
    # Configuration
    HOST = '127.0.0.1'
    PORT = 42069
    CT = base64.b64decode("RWNwJGx1cyhsY2VpLWVgYjYEGFRJFhpUFgoGCVUOHAFSam81bF58P3dyZGYwdBETQ3h8IXlIayduaH96LWoOEw==")
    IV = base64.b64decode("dxTwbO/hhIeycOTbTnp8QQ==")
    
    # Execute attack
    print("Starting padding oracle attack...")
    try:
        attack = PaddingOracleAttack(HOST, PORT)
        plaintext = attack.decrypt(IV, CT)
        print(f"Decryption successful!")
        print(f"Plaintext: {plaintext}")
        print(f"Base64 encoded: {base64.b64encode(plaintext).decode()}")
    except Exception as e:
        print(f"Attack failed: {e}")

if __name__ == "__main__":
    main()
