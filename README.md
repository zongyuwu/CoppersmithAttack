# CoppersmithAttack
Coppersmith's theorem has many applications in attacking RSA specifically if the public exponent e is small or if partial knowledge of the secret key is available.

  * LowPublicExponent: When e is small and doesnot padding. Contain two case "trival", "Håstad" case  
    * Trivial case: If m^3 < N then we can only compute cuberoot(m^3)  
    * Hastad case: If m^3 > N but we have multiple pair of c,n
