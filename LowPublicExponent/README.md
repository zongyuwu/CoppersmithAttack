http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf  

* When e^3 is smaller then modulus N. Using trivial to solve
Usage  
  `p LowPublicExponent.new.cuberoot(85128828301142484868936198256769000)`
  `a = LowPublicExponent::Trivial.new`
  `a.input("./ciphertext.txt")`
  `p a.Exploit`
