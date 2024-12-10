import base64


from tasks.polynom_perf import Polynom, FieldElement
import random
from common import calc_l, poly_to_b64, pad_ad, pad_slice_ct
from tasks.gcm import ghash

def sff(polynom: 'Polynom'):
    f_ = polynom.derivative()
    if f_.int ==[]:
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
                "factor": x["factor"], # insert Jonathan Frakes meme here

                "exponent": 2 * x["exponent"]            
            })
    return sort_polynomials_with_key(factors, "exponent")  


def ddf(polynom: 'Polynom'):
    q = 1<<128
    z = []
    d = 1
    f_ = polynom
    while f_.degree()>=2*d:
        X = Polynom([0, 1])

        h_ = X.poly_powmod(f_, (q**d))
        h = h_+X
        g = h.gcd(f_)
        if g.int != [1]:
            z.append({
                "factor":g.int,
                "degree": d
            })
            f_,_ = f_/g
        d +=1
    if f_.int != [1]:
        z.append({
            "factor": f_.int,
            "degree":f_.degree()
        })
    elif z == []:
        z.append({
            "factor":polynom.int,
            "degree":1
            
        })
        
    return sort_polynomials_with_key(z, "degree")

def sort_polynomials_with_key(data: list, key: str):
    """
    Sort Polynomials based on a key, f.e. Degree of Exponent

    Args:
        data: Array of Polynomials
        key: String
    Returns:
        Sorted_data: List of sorted polynomials with their key
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
     
    return sorted_data # Stop searching once the match is found
    
def rand_poly(bound) -> Polynom:
    """
    Generates a random polynom with degree lower then the input.

    Args:
        Bound: Degree Boundary
    Returns:
        Random Polynom with degree with degree bound-1
    """

    rand_elements = []
    magic_value = (1<<128)-1
    bound_rand = random.randint(0, bound-1)
    for _ in range(bound_rand):
        rand_elements.append(random.randint(0,magic_value))
    rand_elements.append(random.randint(1, magic_value))
    return Polynom(rand_elements)
        

def edf(polynom: 'Polynom', d: int) -> list:
    # d is degree val
    # polynom is corresponding poly
    # This is  garbage <- Not anymore
    
    f = polynom
    q = 1<<128
    n = polynom.degree()/d
    z = []
    z.append(f.int)
    
    while len(z)<n:

        h = rand_poly(f.degree())
        g_ = ((q**d)-1)//3
        g = h.poly_powmod(f, g_) + Polynom([1])
        
        for u in z.copy():
            u_ = Polynom(u)
            
            if u_.degree()>d:
                j = u_.gcd(g)
                
                
                if (j.int != [1]) and (j != u_):
                    
                    z.append(j.int)
                    u_div_j,_ = u_/j
                    z.append(u_div_j.int)
                    z.remove(u)
    
    polys_obj = [Polynom(group) for group in z]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    return sorted_polynomials

def constr_ghash_poly(ciphertext: str, ad: bytes, tag: bytes):
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

    ghash_poly.append(int.from_bytes(tag,'little'))
    
    #print(ad_blocks)
    #print(ct_block_int)
    
    # Reverse to get ghashpoly in correct order 
    ghash_poly.reverse()
    
    return Polynom(ghash_poly)

def gcm_crack(poly1: 'Polynom', poly2: 'Polynom', ad_m1, ct_m1, tag_m1, ad_m3, ct_m3, m3_tag, fg_ct, fg_ad):
    x = FieldElement(0)
    m3_tag = x.gcm_sem(int.from_bytes(base64.b64decode(m3_tag), 'little'))

    ghash_poly_ = poly1 + poly2

    ghash_poly =  ghash_poly_.gfpoly_makemonic()
    ghash_poly = Polynom(ghash_poly)
    
    square_free_poly = sff(ghash_poly)
    #print(f"SFF RES: {square_free_poly}\n")
    

    res = []
    for _, entry in enumerate(square_free_poly):
        ddf_poly = Polynom(entry['factor'])
        #print(f"DDF Poly: {ddf_poly.int}\n")
        dist_deg_poly = ddf(ddf_poly)
        #print(f"Dist deg poly: {dist_deg_poly}")
        res.append(dist_deg_poly)
         
    #print(f"DDF RES: {res}\n")
    
    edf_candidates = [
        entry['factor']
        for sublist in res
        for entry in sublist
        if entry['degree'] ==1
    ]
    #print(f"EDF candidates: {edf_candidates}\n")
    
    ad_blocks_m1= pad_ad(ad_m1)
    ad_blocks_m3 = pad_ad(ad_m3)

    ct_m1_ = pad_slice_ct(ct_m1)
    ct_m3_ = pad_slice_ct(ct_m3)
    

    L_m1 = calc_l(ad_m1, ct_m1) 
    L_m3 = calc_l(ad_m3, ct_m3)

    l_fe_m1 = FieldElement(int.from_bytes(L_m1, 'little'))
    l_fe_m3 = FieldElement(int.from_bytes(L_m3, 'little'))

    for candidate in edf_candidates:
        edf_poly = Polynom(candidate)
        #print(f"Edf poly:{edf_poly.int}")
        res = edf(edf_poly, 1)
        for polynom in res:
            for element in polynom.int:
                if element !=1:
                    h = x.gcm_sem(element)
                    h = FieldElement(h)
                    ghash_res_ek = ghash(ad_blocks_m1,h,l_fe_m1, ct_m1_)
                    #print(f"Ghash res: {ghash_res_ek.element}")
                    tag = FieldElement(x.gcm_sem(int.from_bytes(tag_m1, 'little')))
                    eky_0 = ghash_res_ek+tag
                    #print(f"EKY_0 : {eky_0.element}")
                    ghash_m3 = ghash(ad_blocks_m3,h, l_fe_m3, ct_m3_)
                    #print(f"Ghash m3: {ghash_m3.element}")
                    tag = ghash_m3 + eky_0
                    #print(f"Tag m3: {base64.b64encode(int.to_bytes(x.gcm_sem(tag.element), 16, 'little')).decode()}")
                    #print(f"Tag given: {base64.b64encode(int.to_bytes(x.gcm_sem(m3_tag), 16, 'little')).decode()}")
                    
                    if tag.element == m3_tag:
                        L_fg = calc_l(fg_ad, fg_ct)
                        ad_blocks_fg = pad_ad(fg_ad)
                        ct_fg = pad_slice_ct(fg_ct)
                        L_fg_fe = FieldElement(int.from_bytes(L_fg, 'little'))
                        forgery_result = ghash(ad_blocks_fg,h, L_fg_fe, ct_fg)
                        forgery_tag = forgery_result + eky_0
                        return forgery_tag, h, eky_0
    return None
