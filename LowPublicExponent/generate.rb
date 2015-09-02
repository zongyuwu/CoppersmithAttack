#!/usr/bin/env ruby

require 'openssl'
require 'base64'

Test_dir = "./test/"
Plaintext_tri = "#{Test_dir}plaintext_tri.txt"
Ciphertext_tri = "#{Test_dir}ciphertext_tri.txt"
PrivateKey_tri = "#{Test_dir}priv_tri.pem"

Plaintext = "#{Test_dir}plaintext.txt"
Ciphertext = ["ciphertext1.txt", "ciphertext2.txt", "ciphertext3.txt"].map! { |v| v = "#{Test_dir}#{v}" }
PrivateKey = ["priv1.pem", "priv2.pem", "priv3.pem"].map! { |v| v = "#{Test_dir}#{v}" }

class Gen
  def initialize(e, bit, pt)
    @rsa = OpenSSL::PKey::RSA.new(bit, e)
    @N = @rsa.params["n"].to_i
    @M = readtext(pt)
    @E = e.to_i
    @C = enc
  end

  def writepri(fpriv)
    File.open(fpriv, "w") { |f| f.write(@rsa.to_pem) }
  end

  def writecip(cpriv)
    File.open(cpriv, "w") { |f| f.write(@C) }
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

s = Gen.new(3, 1024, Plaintext_tri)
s.writepri(PrivateKey_tri)
s.writecip(Ciphertext_tri)
#s.dec

PrivateKey.zip(Ciphertext).each do |p, c|
  s = Gen.new(3, 1024, Plaintext)
  s.writepri(p)
  s.writecip(c)
end
