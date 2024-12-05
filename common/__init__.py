import base64 
from tasks.polynom import FieldElement, Polynom
def slice_input(input) -> list:
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

BIT_REVERSE_TABLE = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]


def _base64_to_poly(poly):
        """
        Convert base64-encoded coefficients to integers in GCM semantic.
        
        Transforms each coefficient into the bit representation required
        for GCM's field arithmetic implementation.
        
        Returns:
            List of integers representing coefficients in GCM semantic
        """
        integer_list = []
        field_element = FieldElement(0)  # Create a FieldElement instance to use gcm_sem
    
        for b46str in poly:
            bytes_val = base64.b64decode(b46str)
            int_val = int.from_bytes(bytes_val, 'little')
                # Convert to GCM semantic using the FieldElement's gcm_sem method
            gcm_val = field_element.gcm_sem(int_val)
            integer_list.append(gcm_val)
        return Polynom(integer_list)

def reverse_bits_with_table(byte_val):
    """
    Reverse the bits of a byte using the BIT_REVERSE_TABLE.
    
    Args:
        byte_val (int): A byte (0-255) whose bits need to be reversed.
    
    Returns:
        int: The bit-reversed byte.
    """
    return BIT_REVERSE_TABLE[byte_val]

def poly_to_b64(poly):
    """
    Convert polynomial integer coefficients (in GCM semantic) to base64-encoded strings after bit reversal.
    
    Each integer in the polynomial is bit-reversed at the byte level, converted to bytes, and then base64 encoded.
    
    Returns:
        List of base64-encoded strings representing the polynomial coefficients.
    """
    integer_list = []
    
    for value in poly:
        # Convert the integer value to a byte array (16 bytes for 128 bits)
        byte_array = value.to_bytes(16, 'little')  # 16 bytes = 128 bits
        
        # Reverse the bits within each byte using the BIT_REVERSE_TABLE
        reversed_byte_array = bytearray(reverse_bits_with_table(byte) for byte in byte_array)
        
        # Encode the reversed byte array into base64
        base64_encoded = base64.b64encode(reversed_byte_array).decode()
        
        # Append the base64-encoded string to the result list
        integer_list.append(base64_encoded)
    return integer_list
def transform_sort(input, key):
     return [{"factor": poly_to_b64(item["factor"]), key: item[key]} for item in input 
]

def gcm_sem(element) -> int:
        """ 
        Transform a field element to GCM's semantic.

        Performs bit reversal on individual bytes as required by GCM's
        field arithmetic implementation

        Args:
            element: Field element as int

        Returns:
            transformed element
        """
        
        element = element.to_bytes(16, 'little') 
        reversed_element = bytes(BIT_REVERSE_TABLE[b] for b in element)
        return int.from_bytes(reversed_element, 'little')

