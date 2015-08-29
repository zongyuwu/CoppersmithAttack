REF
http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf  
https://en.wikipedia.org/wiki/Coppersmith's_Attack  
http://crypto.stackexchange.com/questions/6713/low-public-exponent-attack-for-rsa  
https://en.wikipedia.org/wiki/Chinese_remainder_theorem#Existence  


* When m^e is smaller than modulus N. Using trivial to solve
Usage  
  `p LowPublicExponent.new.cuberoot(85128828301142484868936198256769000)`  
  `a = LowPublicExponent::Trivial.new`  
  `a.input("./ciphertext.txt")`  
  `p a.exploit`  

* When m^e is bigger than modulus N. But you have C1, C2... and N1, N2..
  `p LowPublicExponent::HastadBroadcastAttack.new([c1,n1], [c2,n2] ...).exploit`
  `a = LowPublicexponent::HastadBroadcastAttack.new`
  `a.cipherin("./ciphertext.txt")`
  `a.cipherin("./ciphertext2.txt")`
  `a.modulusin("./pub.pem")
  `a.modulusin("./pub2.pem")
  `p a.exploit`
