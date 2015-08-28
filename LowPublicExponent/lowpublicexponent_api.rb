#!/usr/bin/env ruby
#https://en.wikipedia.org/wiki/Coppersmith's_Attack
#http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf

class LowPublicExponent
  #REF http://stackoverflow.com/questions/15529205/ruby-sqrt-on-a-very-large-integer-cause-rounding-issues
  def cuberoot a
    begv = 1
    endv = a
    while endv > begv + 1
      mid = (endv + begv)/2
      if mid ** 3 <= a
        begv = mid
      else
        endv = mid
      end
    end
    return begv
  end

  def readfiletoint(file)
    return File.read(file).unpack("H*")[0].to_i(16)
  end

  def inttostring(c)
    c_chr = ""
    until c == 0
      c_chr = "#{c_chr}#{(c%(16**2)).chr}"
      c /= (16**2)
    end
    return c_chr.reverse
  end

  class Trivial < LowPublicExponent
    def initialize(c=nil)
      @C = c
    end

    def input(file)
      @C = readfiletoint(file)
    end

    def Exploit
      raise "No input ciphertext" if @C.nil?
      return inttostring(cuberoot(@C))
    end
  end
  
  class CRT < LowPublicExponent
    def initialize()
    end
  end
end

#p LowPublicExponent.new.cuberoot(85128828301142484868936198256769000)
#a = LowPublicExponent::Trivial.new
#a.input("./ciphertext.txt")
#p a.Exploit
