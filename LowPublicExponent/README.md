**Introduction**  
Håstad's Broadcast Attack is used when e is small and no padding.  
Read REF for futher information  

**Tool**
* Trival case  
  * Read ciphertext from file  
  `./lowpublicexponent.rb -t -f "(ciphrtext3.txt,)"`  
  * Read ciphertext from argv (need to be an integer)
  `./lowpublicexponent.rb -t -i "(1123130932,)"`  

* Hastad case  
  * Read ciphertext and modulus from file  
  `./lowpublicexponent.rb -f "(ciphertext.txt,pub.pem),(ciphertext1.txt,pub1.pem),(ciphertext2.txt,pub2.pem)....."`  
  * Read ciphretext and modulus from argv (need to be an integer)  
  `./lowpublicexponent.rb -i "(c1 in int),(n1 in int),(c2 in int,n2 in int)....."`  


**API**
* When m^e is smaller than modulus N. Using trivial to solve  
Usage  
```ruby
  p LowPublicExponent.new.cuberoot(85128828301142484868936198256769000) # or just use tool
  a = LowPublicExponent::Trivial.new
  a.input("./ciphertext.txt") #read cipher text from file
  p a.exploit
  # if the e is not = 3 try
  p a.exploit(e)

```  
* When m^e is bigger than modulus N. But you have C1, C2... and N1, N2..

```ruby
  p LowPublicExponent::HastadBroadcastAttack.new([c1,n1], [c2,n2] ...).exploit #initial with [c,a]
  a = LowPublicexponent::HastadBroadcastAttack.new
  # Read c and n from file
  a.cipherin("./ciphertext.txt")
  a.cipherin("./ciphertext2.txt")
  a.modulusin("./pub.pem")
  a.modulusin("./pub2.pem")
  p a.exploit
  # if the e is not = 3 try
  p a.exploit(e)
```



REF  
http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf  
https://en.wikipedia.org/wiki/Coppersmith's_Attack  
http://crypto.stackexchange.com/questions/6713/low-public-exponent-attack-for-rsa  
ttps://en.wikipedia.org/wiki/Chinese_remainder_theorem#Existence  
