#!/usr/bin/env ruby
#https://en.wikipedia.org/wiki/Coppersmith's_Attack
#http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf

require 'openssl'

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
    #The case when m^e is less than N
    def initialize(c=nil)
      @C = c
    end

    def input(file)
      @C = readfiletoint(file)
    end

    def exploit
      raise "No input ciphertext" if @C.nil?
      return inttostring(cuberoot(@C))
    end
  end
  
  class HastadBroadcastAttack < LowPublicExponent
    def initialize(*cn)
        @N, @C = [], []
      cn.each do |cn|
        @N << cn[1] 
        @C << cn[0]
      end
    end

    def cipherin(file)
      @C << readfiletoint(file)
    end

    def modulusin(file)
      rsa = OpenSSL::PKey::RSA.new File.read(file)
      @N << rsa.params["n"].to_i
    end

    def exploit
      raise "Bad Argument" if sanitycheck() == false
      #crt(@C, @N)
      inttostring(cuberoot(crt(@C, @N)))
    end

  private
    def crt(remainders, mods) 
      max = mods.inject(1, :*)
      sum = 0
      remainders.zip(mods).each do |r, m|
        sum += (r*(max/m)*invmod(max/m, m))
      end
      return sum % max
    end

    def extended_gcd(a, b)
      last_remainder, remainder = a.abs, b.abs
      x, last_x, y, last_y = 0, 1, 1, 0
      while remainder != 0
        last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
        x, last_x = last_x - quotient*x, x
        y, last_y = last_y - quotient*y, y
      end
      return last_remainder, last_x * (a < 0 ? -1 : 1)
    end
 
    def invmod(e, et)
      g, x = extended_gcd(e, et)
      if g != 1
        raise 'Teh maths are broken!'
      end
      x % et
    end

    def sanitycheck
      return false if @N.length != @C.length
      @N.zip(@C) do |n,c|
        return false if n <= c
      end
      return true
    end

  end
end

=begin
a = LowPublicExponent::HastadBroadcastAttack.new
a.cipherin("ciphertext.txt")
a.cipherin("ciphertext1.txt")
a.cipherin("ciphertext2.txt")
a.modulusin("priv.pem")
a.modulusin("priv1.pem")
a.modulusin("priv2.pem")
p a.exploit
=end
