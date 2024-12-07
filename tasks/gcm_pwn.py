import random, base64
from tasks.polynom import Polynom
from tasks.poly import poly2block, poly2block_gcm

def sff(polynom: 'Polynom'):
    f_ = polynom.derivative()
    if f_.polynomials ==[]:
        
        #FIX: Remove magiv value, replace with poly2block
        f_ = Polynom(["AAAAAAAAAAAAAAAAAAAAAA=="])
    c = polynom.gcd(f_)
    f, _ = polynom / c
    factors = []
    e = 1
    
    while f.polynomials_int_gcm != [1]:
        y = f.gcd(c)
        if y != f:
            x, _ = f/y
            # Only add factor if it's not a trivial single-term polynomial
            if x.polynomials_int_gcm != [1]:
                factors.append({
                    "factor": x.polynomials,
                    "exponent": e
                })
        f = y
        c, _ = c/y
        e += 1

    if c.polynomials_int_gcm != [1]:
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
    while (len(f_.polynomials_int_gcm)-1)>=2*d:
        X = Polynom([poly2block([0]), poly2block_gcm([1])])

        h_ = X.poly_powmod(f_, (q**d))
        h = h_+X
        g = h.gcd(f_)
        if g.polynomials_int_gcm != [1]:
            z.append({
                "factor":g.polynomials,
                "degree": d
            })
            f_,_ = f_/g
        d +=1
    if f_.polynomials_int_gcm != [1]:
        z.append({
            "factor": f_.polynomials,
            "degree":len(f_.polynomials)-1
        })
    elif z == []:
        z.append({
            "factor":polynom.polynomials,
            "degree":1
            
        })
        
    return sort_polynomials_with_key(z, "degree")

def sort_polynomials_with_key(data, key):
    polys_obj = [Polynom(item["factor"]) for item in data]
    
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    
    
    sorted_data = []
    for poly in sorted_polynomials:
        poly_factors = poly.polynomials
        for item in data:
            if item["factor"] == poly_factors:
                sorted_data.append({
                    "factor": item["factor"],
                    key: item[key]
                })
                break  
    
    return sorted_data

def rand_poly(bound):
    rand_elements = []
    magic_value = (1<<128)-1
    bound_rand = random.randint(0, bound-1)
    for _ in range(bound_rand):
        rand_elements.append(base64.b64encode(int.to_bytes((random.randint(0,magic_value)), 16, 'little')).decode())
    
    rand_elements.append(base64.b64encode(int.to_bytes((random.randint(1,magic_value)), 16, 'little')).decode())
    
    return Polynom(rand_elements)
        

def edf(polynom: 'Polynom', d: int) -> list:
    # d is degree val
    # polynom is corresponding poly
    # This is  garbage <- Not anymore
    
    f = polynom
    q = 1<<128
    n = (len(polynom.polynomials)-1)/d
    z = []
    z.append(f.polynomials)
    
    while len(z)<n:

        h = rand_poly(len(f.polynomials)-1)
        g_ = ((q**d)-1)//3
        g = h.poly_powmod(f, g_) + Polynom([poly2block_gcm([0])])
        
        for u in z.copy():
            u_ = Polynom(u)
            
            if (len(u_.polynomials_int)-1)>d:
                j = u_.gcd(g)
                
                
                if (j.polynomials_int_gcm != [1]) and (j != u_):
                    
                    z.append(j.polynomials)
                    u_div_j,_ = u_/j
                    z.append(u_div_j.polynomials)
                    z.remove(u)
    
    polys_obj = [Polynom(group) for group in z]
    sorted_polynomials = polys_obj[0].gfpoly_sort(*polys_obj[1:])
    z_sorted = [p.polynomials for p in sorted_polynomials]
    
    return z_sorted



