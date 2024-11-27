from tasks.polynom import Polynom,FieldElement
from tasks.poly import poly2block, poly2block_gcm

def sff(polynom: 'Polynom'):
    f_ = polynom.derivative()
    if f_.polynomials ==[]:
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
