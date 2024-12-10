
# KAUMA (Kryptoanalysis und Methoden Audit)

This is my submission for the KAUMA labwork assignment at DHBW Mannheim. This tool implements various cryptographic operations and functions.  
The tool processes JSON-formatted input files, performs the requested cryptographic operations, and returns standardized results. 

## Features

KAUMA implements several cryptographic operations and methods:

- **Polynomial Operations**
  - Comprehensive arithmetic in GF(2^128)
  - Conversion between polynomial and block representations
  - Support for both standard and GCM semantics
  - Derivative calculation for polynomials (removes even-degree terms and 0-degree term)
  - GCD calculation for two polynomials
  - Sorting of polynomials

- **Cryptographic Primitives**
  - SEA-128 encryption and decryption
  - Galois Field multiplication
  - XEX mode operations

- **Advanced Modes of Operation**
  - GCM (Galois/Counter Mode) encryption and decryption
  - Support for multiple block ciphers (AES-128, SEA-128)

- **PKCS#7 Padding Cracking via Padding Oracle Attack**
  - Retrieve plaintext by cracking its PKCS#7 padding given a vulnerable server
  - Note: This implementation uses a specific binary protocol to communicate. If you want to use it with your server, you have to adjust the communication.

- **Factorization Algorithms**
  - SFF: Factorize a Polynomial into its square free factors
  - DDF: Factorize a Polynomial into its distint degree factors
  - EDF: Factorize a Polynomial into its equal degree Factors

- **AES GCM Full Break on Nonce reuse**
  - Break AES GCM on nonce reuse and recover the authentication key and mask
  - Authenticate a forged message

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

## Core Components

### 1. Field Operations in GF(2^128)

#### FieldElement Class
- Represents individual elements in GF(2^128)
- Handles GCM semantic conversions required for Galois Counter Mode operations
- Supports fundamental field operations:
  - Addition (XOR operation)
  - Multiplication (using Russian peasant algorithm)
  - Division (through multiplicative inverse)
  - Square root
- Elements are initialized with integers and automatically handle modular reduction

Example usage:
```python
# Create field elements
a = FieldElement(123)
b = FieldElement(456)

# Perform operations
sum_result = a + b    # Field addition
prod_result = a * b   # Field multiplication
div_result = a / b    # Field division
sqrt_result = a.sqrt() # Square root
```

### 2. Polynomial Operations

#### Polynom Class
- Works with polynomials whose coefficients are elements of GF(2^128)
- Coefficients are represented as base64-encoded strings
- Handles both standard and GCM semantic representations
- Supports comprehensive polynomial operations:
  - Addition: Coefficient-wise XOR operation
  - Multiplication: Standard polynomial multiplication with field arithmetic
  - Division: Returns both quotient and remainder
  - Modular exponentiation
  - Sorting polynomials by degree and coefficient values
  - Converting polynomials to monic form
  - Derivatives: Removes even-degree terms and 0-degree term (implemented in `derivative` method)
  - GCD: Calculates the greatest common divisor of two polynoms
  
Example usage:
```python
# Create polynomials with base64-encoded coefficients
# Each coefficient represents a field element
# Highest degree term is rightmost in the list
p1 = Polynom(["AAAAAAAAAAAAAAAAAAAAAA==", "gAAAAAAAAAAAAAAAAAAAAA=="])  # x + 1
p2 = Polynom(["gAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAA=="])  # 1 + x

# Perform operations
sum_poly = p1 + p2    # Polynomial addition
prod_poly = p1 * p2   # Polynomial multiplication
quotient, remainder = p1 / p2  # Polynomial division
exp_poly = p1 ** 3    # Polynomial exponentiation
p1.gcd(p2)
monic_coeffs = p1.gfpoly_makemonic()  # Convert to monic form

# Sort multiple polynomials
sorted_polys = p1.gfpoly_sort(p2, p3)

# Derivative of polynomial
derivative_poly = p1.derivative()  # Remove even-degree terms and 0-degree term
```

#### GCM Semantic
The implementation handles two different bit representations:
1. Standard representation: Used for normal arithmetic operations
2. GCM semantic: Required for Galois Counter Mode operations
   - Involves bit reversal within each byte
   - conversions for Polynomials through `_base64_to_poly` and `poly_to_b64`
   - conversion for Field Elements through `FieldElement.gcm_sem(int)`
   - Essential for compatibility with GCM mode encryption

### 3. Polynomial-Block Conversions
- `poly2block`: Convert polynomial coefficients to block representation in XEX semantic
- `block2poly`: Convert block to polynomial coefficients in XEX semantic
- `poly2block_gcm` & `block2poly_gcm` support GCM semantics

### 4. SEA-128 Operations
- Encryption and decryption using SEA-128 algorithm
- 128-bit key and block size
- `sea_enc` encrypts input using SEA-128
- `sea_dec` decrypts input using SEA-128

### 5. XEX Mode
- Tweakable block cipher mode
- `XEX` class with methods `.xex_round_enc` and `.xex_round_dec` provide encryption and decryption operations
- Uses FieldElement class for GF(2^128) operations

### 6. GCM Mode
- Authenticated encryption with associated data
- `GCM_encrypt`, `GCM_decrypt` uses AES-128/SEA-128 as the underlying block cipher, depending on a given key

### 7. PKCS#7 Padding Oracle Attack
- `padding_oracle_crack` function
- Decrypt a PKCS#7 padding given a hostname (for the vulnerable server), port, initialization vector (IV) and ciphertext

### Square Free Factorization
  - `sff(Polynomial)` function
  - Factorizes a Polynomial into its square free factors

### Distinct Degree Factorization
  - `ddf(Polynomial)` function
  - Factorizes a monic square free Polynomial into its distinct degree factors

### Equal Degree Factorization - Cantor Zassenhaus Algorithm
  - `edf(Polynomial, degree)` function
  - Factorizes a square free monic Polynomial which is a product of Polynoms of Degree d into its equal degree factors

### GCM Crack Attack
  - `gcm_crack()` function
  - Achieve a full break on AES GCM given 3 messages authenticated with the same nonce
  - Outputs the authentication key h, mask and the newly generated tag for a forged message


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
├── kauma            # Script to run the program 
├── tests            # Script to run unit tests defined in common/tests
├── kauma_conditional_mp.py         # Entry point, gets executed when running kauma and parses the data to the differet functions. Uses multi processing
├── tests.py         # Unit tests
├── tasks/           # Cryptographic implementations
│   ├── poly.py      # Polynomial operations
│   ├── sea.py       # SEA-128 implementation
│   ├── gfmul.py     # Field multiplication
│   ├── xex.py       # XEX mode
│   ├── gcm.py       # GCM encryption and decryption using AES or SEA
│   ├── padding_oracle_crack.py  # PKCS#7 padding oracle attack
│   ├── server.py    # Demo oracle server
│   └── polynom_perf.py   # Operations with Polynomials in GF(2^128)
│   └── gcm_pwn.py   # Factorization Algorithms for Polynomials including AES GCM crack
├── common/          # Shared utilities and common functions
│   ├── common.py    # Includes a function to write errors to stderr
└── json/            # Testcase files for various functions

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


