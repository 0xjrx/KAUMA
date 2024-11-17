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

- **PKCS#7 Padding craking via padding oracle attack**
  - Retreive Plaintext by cracking its PKCS#7 Padding given a vulnerable Server
  - Note: This implementation uses a specfic binary protocol to communicate. If you want to use it with your
  server you have to adjust the communication

- **Polnomial Operations in GF 2^128**
  - Addition of polynomials and field elements in GF 2^128
  - Multiplication of polynomials and field elements in GF 2^128
  - Exponeniation of polynomials and field elements in GF 2^128
  - Division of polynomials and field elements in GF 2^128
  - Sorting of polynomials
  - Converting polynomials into a monic version

## Installation

```bash
# Download the release or clone the repository
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
An example file is `test.json`. This can be used to test all functions.

### Supported Operations

#### 1. Polynomial-Block Conversions
- `poly2block`: Convert polynomial coefficients to block representation in XEX semantic
- `block2poly`: Convert block to polynomial coefficients in XEX semantic
- `poly2block_gcm` & `block2poly_gcm` support GCM semantics

#### 2. SEA-128 Operations
- Encryption and decryption using SEA-128 algorithm
- 128-bit key and block size
- `sea_enc` encrypts and input using SEA-128
- `sea_dec` decrypts an input using SEA-128

#### 3. Field Operations
- `gfmul`: Galois Field multiplication, supports xex semantic

#### 4. XEX Mode
- Tweakable block cipher mode
- `XEX` class with function `.xex_round_enc` and `.xex_roud_dec` provide encryption and decryption operations
- `FieldElementGCM` class provides easy addition and multiplication within GF(2^128)

#### 5. GCM Mode
- Authenticated encryption with associated data
- `GCM_encrypt`, `GCM_decrypt` uses AES-128 as the underlying block cipher
- `GCM_encrypt_sea`, `GCM_decrypt_sea` uses SEA-128 as the underlying block cipher

#### 6. PKCS#7 Padding Cracking using a vulnerable padding oracle
- `padding_oracle_crack` function
- Decrypt a PKCS#7 Padding given a hostname (for the vulnerable server), port, initialization vector (IV) and ciphertext

#### 7. Polynomial Operations
- `FieldElement` class with overloaded operators for easy operations
- Use the overloaded operators `+`, `*`, `**`, `/` to perform operations with Field Elements
- Field Elements are instantiated by creating a FieldElement() object that takes an integer
- The `Polynom` class on the other hand works by taking a list of Base64 strings, each representing a factor of the polynomial
with the higest degree on the right. You can think of each factor as a Field Element
- Use operators such as `+`, `*`, `**`, `/` to perform arithmetic operations with polynomials
- As of now you can also call the instancemethods `grpoly_sort` which sorts multiple polynomials
and `gfpoly_makemonic` which, as the name suggests, makes a polynomial monic, dividing every FieldElement by the highest coefficients of the polynomial


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
│   └── parser_mp.py  # Parser for input with multiprocessing
│   └── padding_oracle_crack.py      # PKCS#7 padding oracle attack
│   └── server.py     # Demo oracle server
│   └── polynom.py    # Operations with Polynomials in GF 2^128
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

