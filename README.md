# KAUMA (Kryptoanalysis und Methoden Audit)

This is my submission for the KAUMA labwork assignment at DHBW Mannheim. This tool, implements various cryptographic operations and functions.
The tool processes JSON-formatted inputs files, performs the requested cryptographic operations and returns standardized results. 

## Features

KAUMA implements several cryptographic operations and methods:

- **Polynomial Operations**
  - Conversion between polynomial and block representations
  - Support for both XEX and GCM semantics

- **Cryptographic Primitives**
  - SEA-128 encryption and decryption
  - Galois Field multiplication
  - XEX mode operations

- **Advanced Modes of Operation**
  - GCM (Galois/Counter Mode) encryption and decryption
  - Support for multiple block ciphers (AES-128, SEA-128)

## Installation

```bash
# Clone the repository
git clone https://github.com/0xjrx/kauma.git

# Navigate to the project directory
cd kauma

# Install poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies using Poetry
poetry install

# Activate the virtual environment
poetry shell

```

## Usage

### Basic Usage

```bash
bash kauma input.json
```

### Input Format

KAUMA accepts JSON files containing test cases for various cryptographic operations. Each test case specifies an action and its required arguments.

Example input file:
```json
{
    "testcases": {
        "b3665760-023d-4b08-bad2-15d2b6da22fe": {
          "action": "gcm_encrypt",
          "arguments": {
            "algorithm": "aes128",
            "nonce": "4gF+BtR3ku/PUQci",
            "key": "Xjq/GkpTSWoe3ZH0F+tjrQ==",
            "plaintext": "RGFzIGlzdCBlaW4gVGVzdA==",
            "ad": "QUQtRGF0ZW4="
      }
    }    
  }
}

```

### Supported Operations

#### 1. Polynomial-Block Conversions
- `poly2block`: Convert polynomial coefficients to block representation
- `block2poly`: Convert block to polynomial coefficients
- Supports both XEX and GCM semantics

#### 2. SEA-128 Operations
- Encryption and decryption using SEA-128 algorithm
- 128-bit key and block size

#### 3. Field Operations
- `gfmul`: Galois Field multiplication
- Supports both XEX and GCM field semantics

#### 4. XEX Mode
- Tweakable block cipher mode
- Encryption and decryption operations
- Supports tweaks for domain separation

#### 5. GCM Mode
- Authenticated encryption with associated data
- Supports both AES-128 and SEA-128 as underlying block ciphers
- Provides both encryption and decryption capabilities

### Output Format

KAUMA outputs results in JSON format to stdout:

```json
{
    "responses": {
        "test1": {
            "output": "result_value"
        },
        "test2": {
            "ciphertext": "encrypted_value",
            "tag": "authentication_tag"
        }
    }
}
```


## Project Structure

```
kauma/
├── kauma             # Script to run the programm 
├── tests             # Script to run unit tests defined in common/tests
├── kauma.py          # Entry point, gets executed when running kauma and parses the file tasks/pase.py
├── tasks/            # Cryptographic implementations
│   ├── poly.py       # Polynomial operations
│   ├── sea.py        # SEA-128 implementation
│   ├── gfmul.py      # Field multiplication
│   ├── xex.py        # XEX mode
│   └── gcm.py        # GCM encryption and decryption using AES or SEA
│   └── parse.py      # Parser for input
└── common/           # Shared utilities and common functions
    └── common.py     # Includes a function to write errors to stderr
    └── tests.py      # Includes unit tests
```

## Development

### Adding New Operations

To add new cryptographic operations:

1. Create implementation in the `tasks/` directory
2. Add handling in the parser class
3. Update documentation with new operation details

### Testing

Create unit test in common/tests.py with test cases to verify functionality, then:

```bash
bash tests
```

