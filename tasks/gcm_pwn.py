from tasks.polynom import Polynom

def sff(polynom: 'Polynom'):
    f_ = polynom.derivative()
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
    
    # Random hacky sorting using my gfpoly_sort to sort it the correct way
    return sorted(factors, key=lambda x: polynom.gfpoly_sort(Polynom(x["factor"]))[0].polynomials_int_gcm, reverse=True)
