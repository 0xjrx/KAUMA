import base64
import random

from tasks.polynom_perf import Polynom, FieldElement
from common import calc_l, poly_to_b64, pad_ad, pad_slice_ct
from tasks.gcm import ghash


def sff(polynom):
    """
    Compute the Square-Free Factorization of a polynomial.

    This function finds the square-free factors of a given polynomial over a finite field.
    Square-free factorization breaks down a polynomial into factors that do not have repeated roots.

    Args:
        polynom: The input polynomial to be factorized.

    Returns:
        A list of dictionaries containing the square-free factors and their exponents.
        Each dictionary has two keys:
        - 'factor': The coefficients of the square-free factor
        - 'exponent': The exponent of the factor
    """
    f_ = polynom.derivative()
    if f_.int == []:
        f_ = Polynom([0])
    c = polynom.gcd(f_)
    f, _ = polynom / c
    factors = []
    e = 1
    while f.int != [1]:
        y = f.gcd(c)
        if y != f:
            x, _ = f/y
            # Only add factor if it's not a trivial single-term polynomial
            if x.int != [1]:
                factors.append({
                    "factor": x.int,
                    "exponent": e
                })
        f = y
        c, _ = c/y
        e += 1
    if c.int != [1]:
        r = sff(c.sqrt())
        for x in r:
            factors.append({
                "factor": x["factor"],
                "exponent": 2 * x["exponent"]            
            })
    return sort_polynomials_with_key(factors, "exponent")


def ddf(polynom):
    """
    Compute the Distinct Degree Factorization of a polynomial.

    This function factors a polynomial into irreducible factors of the same degree.

    Args:
        polynom: The input polynomial to be factorized.

    Returns:
        A list of dictionaries containing the factors and their degrees.
        Each dictionary has two keys:
        - 'factor': The coefficients of the factor
        - 'degree': The degree of the factor
    """
    q = 1<<128
    z = []
    d = 1
    f_ = polynom
    while f_.degree() >= 2*d:
        X = Polynom([0, 1])

        h_ = X.poly_powmod(f_, (q**d))
        h = h_+X
        g = h.gcd(f_)
        if g.int != [1]:
            z.append({
                "factor": g.int,
                "degree": d
            })
            f_, _ = f_/g
        d += 1
    if f_.int != [1]:
        z.append({
            "factor": f_.int,
            "degree": f_.degree()
        })
    elif z == []:
        z.append({
            "factor": polynom.int,
            "degree": 1
        })
        
    return sort_polynomials_with_key(z, "degree")


def sort_polynomials_with_key(data, key):
    """
    Sort polynomials based on a specified key.

    Args:
        data: Array of polynomials with their attributes
        key: The key to sort by (e.g., 'degree' or 'exponent')

    Returns:
        Sorted list of polynomials based on the specified key
    """
    polys_obj = [Polynom(item["factor"]) for item in data]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    
    sorted_data = []
    for poly in sorted_polynomials:
        poly_factors = poly_to_b64(poly.int)
        for item in data:
            if poly_to_b64(item["factor"]) == poly_factors:
                sorted_data.append({
                    "factor": item["factor"],
                    key: item[key]
                })
                break
     
    return sorted_data



def rand_poly(bound):
    """
    Generates a random polynomial with degree lower than the input bound.

    Args:
        bound: Maximum degree boundary for the random polynomial

    Returns:
        A random Polynom with a degree less than the specified bound
    """
    rand_elements = []
    magic_value = 2**128
    for _ in range(bound+1):
        rand_elements.append(random.randint(0, magic_value))
    return Polynom(rand_elements)


def edf(polynom, d):
    """
    Perform Equal Degree Factorization on a polynomial.

    Args:
        polynom: The polynomial to be factorized
        d: The degree to use for factorization

    Returns:
        A list of sorted polynomial factors
    """
    f = polynom
    q = 1<<128
    n = polynom.degree()/d
    z = []
    z.append(f.int)
    
    while len(z) < n:
        h = rand_poly(f.degree())
        g_ = ((q**d)-1)//3
        g = h.poly_powmod(f, g_) + Polynom([1])
        
        for u in z.copy():
            u_ = Polynom(u)
            
            if u_.degree() > d:
                j = u_.gcd(g)
                
                if (j.int != [1]) and (j != u_):
                    z.append(j.int)
                    u_div_j, _ = u_/j
                    z.append(u_div_j.int)
                    z.remove(u)
    
    polys_obj = [Polynom(group) for group in z]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    return sorted_polynomials


def constr_ghash_poly(ciphertext, ad, tag):
    """
    Construct a GHASH polynomial from ciphertext, additional data, and tag.

    Args:
        ciphertext: The input ciphertext
        ad: Additional authenticated data
        tag: Authentication tag

    Returns:
        A Polynom representing the GHASH polynomial
    """
    ghash_poly = []
        
    ad_blocks = pad_ad(ad)
    # Convert ad blocks to integers
    ad_block_int = [int.from_bytes(block, 'little') for block in ad_blocks]
    ghash_poly.extend(ad_block_int)

    # Pad ct
    ct = pad_slice_ct(ciphertext)
    ct_block_int = []
    for block in ct:
        ct_block_int.append(int.from_bytes(block, 'little'))
    
    ghash_poly.extend(ct_block_int)

    # Construct L
    L = calc_l(ad, ciphertext) 
    ghash_poly.append(int.from_bytes(L, 'little'))

    ghash_poly.append(int.from_bytes(tag, 'little'))
    
    # Reverse to get ghashpoly in correct order 
    ghash_poly.reverse()
    
    return Polynom(ghash_poly)


def gcm_crack(poly1, poly2, ad_m1, ct_m1, tag_m1, ad_m3, ct_m3, m3_tag, fg_ct, fg_ad):
    """
    Perform a GCM (Galois/Counter Mode) cryptographic crack. We can achieve this full break because
    every input message was encrypted and authenticated with the same nonce.

    This function factorizes the GHASH polynomial for two messages to recover the authentication key, then recovers eky_0
    to authenticate a forged message.

    Args:
        poly1: First input polynomial
        poly2: Second input polynomial
        ad_m1: Additional data for message 1
        ct_m1: Ciphertext for message 1
        tag_m1: Authentication tag for message 1
        ad_m3: Additional data for message 3
        ct_m3: Ciphertext for message 3
        m3_tag: Authentication tag for message 3
        fg_ct: Forgery ciphertext
        fg_ad: Forgery additional data

    Returns:
        A tuple containing forgery tag, hash value, and eky_0(mask), or None if crack fails
    """
    x = FieldElement(0)
    m3_tag = x.gcm_sem(int.from_bytes(base64.b64decode(m3_tag), 'little'))

    ghash_poly_ = poly1 + poly2

    ghash_poly = ghash_poly_.gfpoly_makemonic()
    ghash_poly = Polynom(ghash_poly)
    
    square_free_poly = sff(ghash_poly)

    res = []
    for _, entry in enumerate(square_free_poly):
        ddf_poly = Polynom(entry['factor'])
        dist_deg_poly = ddf(ddf_poly)
        res.append(dist_deg_poly)
    
    edf_candidates = [
        entry['factor']
        for sublist in res
        for entry in sublist
        if entry['degree'] ==1
    ]

    ad_blocks_m1 = pad_ad(ad_m1)
    ad_blocks_m3 = pad_ad(ad_m3)

    ct_m1_ = pad_slice_ct(ct_m1)
    ct_m3_ = pad_slice_ct(ct_m3)

    L_m1 = calc_l(ad_m1, ct_m1) 
    L_m3 = calc_l(ad_m3, ct_m3)

    l_fe_m1 = FieldElement(int.from_bytes(L_m1, 'little'))
    l_fe_m3 = FieldElement(int.from_bytes(L_m3, 'little'))

    for candidate in edf_candidates:
        edf_poly = Polynom(candidate)
        res = edf(edf_poly, 1)
        for polynom in res:
            for element in polynom.int:
                if element != 1:
                    h = x.gcm_sem(element)
                    h = FieldElement(h)
                    ghash_res_ek = ghash(ad_blocks_m1, h, l_fe_m1, ct_m1_)
                    tag = FieldElement(x.gcm_sem(int.from_bytes(tag_m1, 'little')))
                    eky_0 = ghash_res_ek + tag
                    ghash_m3 = ghash(ad_blocks_m3, h, l_fe_m3, ct_m3_)
                    tag = ghash_m3 + eky_0
                    
                    if tag.element == m3_tag:
                        L_fg = calc_l(fg_ad, fg_ct)
                        ad_blocks_fg = pad_ad(fg_ad)
                        ct_fg = pad_slice_ct(fg_ct)
                        L_fg_fe = FieldElement(int.from_bytes(L_fg, 'little'))
                        forgery_result = ghash(ad_blocks_fg, h, L_fg_fe, ct_fg)
                        forgery_tag = forgery_result + eky_0
                        return forgery_tag, h, eky_0
    return None
