#!/usr/bin/env ruby

require 'openssl'
require 'base64'

Plaintext = "./plaintext.txt"
Ciphertext = "./ciphertext3.txt"
PrivateKey = "./priv3.pem"

class Gen
  def initialize(e, bit)
    @rsa = OpenSSL::PKey::RSA.new(bit, e)
    @N = @rsa.params["n"].to_i
    @M = readtext(Plaintext)
    @E = e.to_i
    @C = enc
  end

  def writepri
    File.open(PrivateKey, "w") { |f| f.write(@rsa.to_pem) }
  end

  def writecip
    File.open(Ciphertext, "w") { |f| f.write(@C) }
  end

  def enc
    c = @M.to_bn.mod_exp(@E, @N).to_i
    c_chr = ""
    until c == 0
      c_chr = "#{c_chr}#{(c%(16**2)).chr}"
      c /= (16**2)
    end
    return c_chr.reverse
  end

  def dec
    c = readtext(Ciphertext)
    p = c.to_bn.mod_exp(@rsa.params["d"].to_i, @N).to_i
    p_chr = ""
    until p == 0
      p_chr = "#{p_chr}#{(p %(16**2)).chr}"
      p /= (16**2)
    end
    p_chr.reverse!
    p p_chr
  end

  def readtext(file)
    return File.read(file).unpack("H*")[0].to_i(16)
  end
end

s = Gen.new(3, 1024)
s.writepri
s.writecip
#s.dec
