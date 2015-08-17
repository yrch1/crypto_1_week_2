__author__ = 'yrch'

from Crypto.Cipher import AES
from Crypto import Random

BS = AES.block_size
iv = Random.new().read(BS)


q1Key = '140b41b22a29beb4061bda66b6747e14'
q1CT = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'


q2Key = '140b41b22a29beb4061bda66b6747e14'
q2CT = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'

q3Key = '36f18357be4dbd77f050515c73fcf9f2'
q3CT = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'

q4CT = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'


def aes_cbc_mode_decrypt(key, message):

    obj = AES.new(key, AES.MODE_ECB)
    initialVector = message[0:AES.block_size]

    print 'IV -> ' + initialVector.encode("hex")

    lastPad = initialVector
    result = ""
    for i in range(len(message)/AES.block_size):
        ci = message[AES.block_size*(i+1):AES.block_size*(i+2)]
        mi = strxor(obj.decrypt(ci), lastPad)
        result += mi
        lastPad = ci

    return result


def aes_ctr_mode_decrypt(key, message):

    obj = AES.new(key, AES.MODE_ECB)
    initialVector = message[0:AES.block_size]

    nonceCounter = initialVector
    result = ""

    for i in range(len(message)/AES.block_size):
        ci = message[AES.block_size*(i+1):AES.block_size*(i+2)]
        mi = strxor(ci, obj.encrypt(nonceCounter))
        result += mi
        nonceCounter = nextIV(nonceCounter)
    return result


def nextIV(initialVector):

    nonce = initialVector[0:len(initialVector)/2]
    counter = initialVector[len(initialVector)/2:]

    count = int(counter.encode("hex"),16)
    count += 1

    counter = hex(count)
    counter = counter[2:]
    counter = counter.decode("hex")

    ##print 'nonce -> ' + nonce.encode("hex") + ' counter -> ' +  counter.encode("hex")

    return nonce+counter

#
# xor two strings of different lengths
def strxor(a, b):
    result = ""
    if len(a) > len(b):
        result = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        result = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

    return result

#
# xor two hex-encoded streams, return hex-encoded stream
def xor(m1, m2):
    # which one is shorter? use it to set the end boundary.
    end = len(m1)
    if(len(m2) < len(m1)):
        end = len(m2)

    result = ''
    for i in xrange(0, end, 2):
        n1 = m1[i:i+2]
        n2 = m2[i:i+2]
        b = str(chr((int(n1, 16) ^ int(n2, 16))))
        result += b.encode('hex')
    return result
## end xor()


#
# decryption in CBC is as follows:
#     D(k, ct[0]) xor IV
#     for i=1..n
#         D(k, ct[i]) xor ct[i-1]
def main():

    key = q1Key.decode('hex')

    m1 = aes_cbc_mode_decrypt(key, q1CT.decode("hex"))
    m2 = aes_cbc_mode_decrypt(key, q2CT.decode("hex"))
    print m1
    print m2

    m3 = aes_ctr_mode_decrypt(q3Key.decode("hex"), q3CT.decode("hex"))
    print m3

    m4 = aes_ctr_mode_decrypt(q3Key.decode("hex"), q4CT.decode("hex"))
    print m4


if __name__ == '__main__':
    main()