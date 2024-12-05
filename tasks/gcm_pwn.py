from tasks.polynom import Polynom
import random
from common import poly_to_b64, transform_sort
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
    print(transform_sort(factors, "exponent"))
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

def sort_polynomials_with_key(data, key):
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
    
def rand_poly(bound):
    rand_elements = []
    magic_value = 1<<128-1
    bound_rand = random.randint(1, bound-1)
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

        h = rand_poly(f.degree()-1)
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
    z_sorted = [poly_to_b64(p.int) for p in sorted_polynomials]
    
    return z_sorted

        


