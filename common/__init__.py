import base64 

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
