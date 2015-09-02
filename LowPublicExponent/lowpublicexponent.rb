#!/usr/bin/env ruby
#https://en.wikipedia.org/wiki/Coppersmith's_Attack
#http://www.cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/rsa.pdf

require 'openssl'
require 'optparse'

class LowPublicExponent
  #REF http://stackoverflow.com/questions/15529205/ruby-sqrt-on-a-very-large-integer-cause-rounding-issues
  def cuberoot(a, e=3)
    begv = 1
    endv = a
    while endv > begv + 1
      mid = (endv + begv)/2
      if mid ** e  <= a
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

    def exploit(e=3)
      raise "No input ciphertext" if @C.nil?
      return inttostring(cuberoot(@C, e))
    end
  end
  
  class HastadBroadcastAttack < LowPublicExponent
    def initialize(cn=nil)
      @N, @C = [], []
      if !cn.nil?
        cn.each do |v|
          @N << v[1].to_i
          @C << v[0].to_i
        end
      end
    end

    def cipherin(file)
      @C << readfiletoint(file)
    end

    def modulusin(file)
      rsa = OpenSSL::PKey::RSA.new File.read(file)
      @N << rsa.params["n"].to_i
      e = rsa.params["e"]
      puts "Public Exponet is #{e}"
    end

    def exploit(e=3)
      raise "Bad Argument" if sanitycheck() == false
      #crt(@C, @N)
      inttostring(cuberoot(crt(@C, @N), e))
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

    def invmod(e, et)
      e.to_bn.mod_inverse(et).to_i
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

class ARGVParser
  def initialize
    @@options = {T: false}
    @banner = "Usage lowpublicexponent.rb [options]"
    OptionParser.new do |opts|
      opts.banner = @banner
    
      opts.on("-f F", String, :required, "File to read C,N") do |v|
        @@options[:F] = v 
      end

      opts.on("-i I", String, :required, "Input C,N in integer") do |v|
        @@options[:I] = v
      end

      opts.on("-t", "Trival case") do |v|
        @@options[:T] = true
      end

    end.parse!
    exit if sanitycheck == false
    @farr = @@options[:F].nil? ? nil : file
    @iarr = @@options[:I].nil? ? nil : input 
  end

  def farr
    @farr
  end

  def iarr
    @iarr
  end

  def options
    @@options
  end

private
  def file
    farr = []
    @@options[:F].gsub(/\s+/, "").scan(/\(.+?\)/) do |v| 
      p = v.scan(/[[[:word:]]\.\/]+/)
      farr << [p[0], p[1]]
    end
    #p farr
    return farr
  end

  def input
    iarr = []
    @@options[:I].gsub(/\s+/, "").scan(/\(.+?\)/).each do |v|
      p = v.scan(/[[:digit:]]+/)
      iarr << [p[0], p[1]]
    end
    #p iarr
    return iarr
  end

  def sanitycheck
    if @@options[:F].nil? && @@options[:I].nil? 
      puts "#{@banner} #-h for help"
      return false
    end
  end
end

opts = ARGVParser.new

if opts.options[:T]
  if opts.options[:F].nil?
    opts.iarr.each { |v| p LowPublicExponent::Trivial.new(v[0].to_i).exploit }
  else
    opts.farr.each do |v|
      a = LowPublicExponent::Trivial.new
      a.input(v[0])
      p a.exploit
    end
  end
else
  if opts.options[:F].nil?
    p LowPublicExponent::HastadBroadcastAttack.new(opts.iarr).exploit
  else
    a = LowPublicExponent::HastadBroadcastAttack.new
    opts.farr.each do |v|
      a.cipherin(v[0])
      a.modulusin(v[1])
    end
    p a.exploit
  end
end
