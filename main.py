# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import collections
import binascii
import numpy as np
from BitVector import *
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

AES_modulus = BitVector(bitstring='100011011')


def chunks(hex, n):
    for i in range(0, len(hex), n):
        yield hex[i:i + n]

def file_to_byte(filename):
    bin_data = open(filename, 'rb').read()

    hex_data = binascii.hexlify(bin_data)
    l= len(hex_data) / 32
    #print(type(hex_data))
    print(hex_data)
    hex_data = list(chunks(hex_data, 32))
    #print(hex_data)
    j=0
    key="Thats my Kung Fu"
    filetype = 1
    v = []
    while j< l:
        d = format(int(hex_data[j], 16), "x")
        #print(type(d))
        #print(d)
        #print(j)
        w = []
        h = []
        x = 0
        y = 32
        for i in range(x, y, 2):
            x = i
            w.append(d[x:x + 2][:])

        x = 0
        y = 16
        for i in range(x, y, 4):
            x = i
            h.append(w[x:x + 4][:])
        #h = [v[j*4],v[j*4+1],v[j*4+2],v[j*4+3]]
        #print(h)
        v = v + (encrypt(key,h,filetype))
        j += 1
        #print(j)
    return v


def gethexara(text):
    hexkey = ""
    v = []
    for x in text:
        temp = ord(x)
        temp = format(temp, "x")
        hexkey = hexkey + temp
        v.append(temp)

    #print(v)

    w = []
    x = 0
    y = 16
    for i in range(x, y, 4):
        x = i
        w.append(v[x:x + 4][:])
    return w

def gettext(hex):
    v = []
    text = ""
    j = 0
    while j<len(hex):
        for x in hex[j]:
            i = 0
            while i<4:
                v.append(int(x[i],16))
                i += 1
        t = ''.join(map(chr,v))
        #print(t)
        text = t
        j+=1
    #print(str(t))

    return text


def xor(y,r):
    i=0
    z = []
    while i < len(y):

        bin_a = int(y[i], 16)
        bin_b = int(r[i], 16)
        z.append(format(bin_a ^ bin_b, "x"))
        i += 1
    return z

def gfunc(x ,round):
    g = collections.deque(x)
    g.rotate(-1)
    x = list(g)
    x[0] = format(Sbox[int(x[0], 16)], "x")
    x[1] = format(Sbox[int(x[1], 16)], "x")
    x[2] = format(Sbox[int(x[2], 16)], "x")
    x[3] = format(Sbox[int(x[3], 16)], "x")
    #print(x[3])
    r = [["1", "0", "0", "0"],["2", "0", "0", "0"],["4", "0", "0", "0"],["8", "0", "0", "0"],
         ["10", "0", "0", "0"],["20", "0", "0", "0"],["40", "0", "0", "0"],["80", "0", "0", "0"],
         ["1B", "0", "0", "0"],["36", "0", "0", "0"]]
    x = xor(x, r[round])
    return x


def gen_rkey(w):
    roundkeys = []
    i=4
    while i < 44:
        if i % 4 == 0:
            # print(w[i-1] , w[i-4])
            w.append(xor(gfunc(w[i - 1], int(((i + 1) / 4) - 1)), w[i - 4])[:])
        # print(w[i])
        else:
            # print(w[i - 1] + w[i - 4])
            w.append(xor(w[i - 1], w[i - 4])[:])
        #  print(w)
        if i % 4 == 3:
            roundkeys.append(w[i - 3])
            roundkeys.append(w[i - 2])
            roundkeys.append(w[i - 1])
            roundkeys.append(w[i])
            #print("round", ((i + 1) / 4) - 1, "key", roundkeys[i - 7], roundkeys[i - 6], roundkeys[i - 5], roundkeys[i - 4])
        i += 1
    return roundkeys

def addrkey(p,round,w,rkeys):
    if round==0 : r = [w[0+4*round], w[1+4*round], w[2+4*round], w[3+4*round]]
    else: r = [rkeys[round*4-4],rkeys[round*4-3], rkeys[round*4-2], rkeys[round*4-1]]
    #print(r)
    i = 0
    z = []
    while i < len(r):
        z.append(xor(p[i], r[i]))
        i += 1
    return z
def dc_addrkey(p,round,w,rkeys):
    if round==10 : r = [w[44-4-4*round], w[44-3-4*round], w[44-2-4*round], w[44-1-4*round]]
    else: r = [rkeys[44-round*4-8],rkeys[44-round*4-7], rkeys[44-round*4-6], rkeys[44-round*4-5]]
    #print(r)
    i = 0
    z = []
    while i < len(r):
        z.append(xor(p[i], r[i]))
        i += 1
    return z
def transpos(p):
    i = 0
    trans = p
    while i < 4:
        j=i
        while j < 4:
            temp = trans[i][j]
            trans[i][j] = p[j][i]
            p[j][i] = temp
            #print(i,j," ", j,i)
            j += 1
        i += 1

        #print(" xx")

    return trans
def substut_bytes(p):
    i = 0
    while i < 4:
        j=0
        while j < 4:
            p[i][j] = format(Sbox[int(p[i][j], 16)], "x")
            j += 1
        i += 1
    return p
def inv_substut_bytes(p):
    i = 0
    while i < 4:
        j=0
        while j < 4:
            p[i][j] = format(InvSbox[int(p[i][j], 16)], "x")
            j += 1
        i += 1
    return p


def shift_row(p):

    i = 0
    transpos(p)
    while i < 4:
        g = collections.deque(p[i])
        g.rotate(0-i)
        p[i] = list(g)
        i += 1
    transpos(p)
    return p


def inv_shift_row(p):

    i = 0
    transpos(p)
    while i < 4:
        g = collections.deque(p[i])
        g.rotate(i)
        p[i] = list(g)
        i += 1
    transpos(p)
    return p


def mul(x, y):
    bsum = BitVector(intVal=0, size=8)
    #print(x)
    #print(y)
    for idx in range(len(x)):
        bv1 = x[idx]

        bv2 = BitVector(intVal=int(y[idx], 16), size=8)
        #print(type(bv2))
        bmul = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        bsum = bsum ^ bmul
    return bsum.get_bitvector_in_hex()


def mix_col(mix,state):
    i = 0
    p = []
    #print(mix)
    #print(state)
    while i < 4:
        j = 0
        q = []
        while j < 4:
            q.append(mul(mix[i],state[j]))
            j += 1
        p.append(q)
        i += 1
    transpos(p)
    return p

def inv_mix_col(mix,state):
    i = 0
    p = []
    #print(mix)
    #print(state)
    #transpos(state)
    while i < 4:
        j = 0
        q = []
        while j < 4:
            q.append(mul(mix[i],state[j]))
            j += 1
        p.append(q)
        i += 1
    transpos(p)
    return p


def encrypt(key,val,filetype):
    s = key
    t = val
    tval =[]
    w = []
    m = []

    l = len(t)
    if l > 16:
        j=0
        while j < l:
            temp = t[j:16+j]
            #print(temp)
            #print(len(temp))

            if (len(temp)) < 16:
                pad = 16 - len(temp)
                while pad > 0:
                    temp=temp + " "
                    pad -= 1
            tval.append(temp)
            j += 16
            #print(temp)
            #print(len(temp))

    else:
        pad = 16 - len(t)
        while pad > 0:
            t = t + " "
            pad -= 1
        tval.append(t)
    t = tval
    print(tval)

    if (len(s)) > 16:
        pad = 16
    else:
        pad = 16 - len(s)
    while pad > 0:
        s = s + " "
        pad -= 1
    w = gethexara(s[:])
    print(len(t))
    print("hex of key", w)
    rkeys = gen_rkey(w)


    j=0
    c = []
    while j<len(t):
        rnd = 0
        m = gethexara(t[j])
        print("hex of word", m)
        while rnd < 11:
            if rnd==0 :
                #print("state matrix", m)

                m = addrkey(m, rnd, w, rkeys)
                #print("AES after r",rnd, m)
                #print("")
            elif rnd==10:
                #print("state matrix", m)
                #print(rnd)
                substut_bytes(m)
                #print("subs", m)

                shift_row(m)
                #print("shift row", m)
                m = addrkey(m, rnd, w, rkeys)
                print("AES after round", rnd, " ", m)
                print("")

            else:
                #print("state matrix", m)
                #print(rnd)
                substut_bytes(m)
                #print("subs", m)

                shift_row(m)
                #print("shift row", m)

                m = mix_col(Mixer, m)
                #print("mixed col/ state mat of round 1", m)
                m = addrkey(m, rnd, w, rkeys)
                #print("AES after round",rnd," ", m)
                #print("")

            rnd +=1
        c.append(m)
        j+=1
    return c


def decrypt(cypher,filetype):
    s = key

    if (len(s)) > 16:
        pad = 16
    else:
        pad = 16 - len(s)
    while pad > 0:
        s = s + " "
        pad -= 1
    w = gethexara(s[:])

    # print("hex of word", m)


    rkeys = gen_rkey(w)
    #t = val
    #m = gethexara(t[:])
    #print(m)
    j = 0
    t = []
    while j < len(cypher):
        rnd = 0
        m = cypher[j]
        #print("hex of word", m)
        while rnd < 11:
            if rnd==0 :
                #print("state matrix", m)

                m = dc_addrkey(m, rnd, w, rkeys)
                #print("Inv AES after r",rnd, m)
                #print("")
            elif rnd==10:
                #print("state matrix", m)
                #print(rnd)

                inv_shift_row(m)
                # print("shift row", m)

                inv_substut_bytes(m)
                #print("subs", m)

                m = dc_addrkey(m, rnd, w, rkeys)
                print("Inv AES after round", rnd, " ", m)
                #print("")

            else:
                #print("state matrix", m)
                #print(rnd)

                inv_shift_row(m)
                # print("shift row", m)

                inv_substut_bytes(m)
                #print("subs", m)

                m = dc_addrkey(m, rnd, w, rkeys)
                #print("Inv AES after round",rnd," ", m)

                m = inv_mix_col(InvMixer, m)
                #print("inv mixed col/ state mat of round",rnd, m)

                #print("")
            rnd +=1
        t.append(m)
        j +=1
    return t







key = input("Enter Key")
val = input("Enter Value")
filetype=0
print("key",key)
print("value",val)

# v=file_to_byte("smallest.pdf")
# print(v)

cypher= encrypt(key,val,filetype)
#print(cypher[0])


print("cipher text",gettext(cypher))
print()

texthex = decrypt(cypher,filetype)
#print(texthex)
text = gettext(texthex)
print("original text after decrypt",text)




