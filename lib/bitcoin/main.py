#!/usr/bin/python
from .py2specials import *
from .py3specials import *
import binascii
import hashlib
import re
import sys
import os
import base64
import time
import random
import hmac
from ec_ecdsa import *
from bitcoin.ripemd import *

def privkey_to_address(priv, from_hex=True, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv, from_hex), magicbyte)
privtoaddr = privkey_to_address

# Hashes
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = ''
    try:
        digest = hashlib.new('ripemd160', intermed).digest()
    except:
        digest = RIPEMD160(intermed).digest()
    return digest

def hash160(string):
    return safe_hexlify(bin_hash160(string))

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string, 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))

def bin_ripemd160(string):
    try:
        digest = hashlib.new('ripemd160', string).digest()
    except:
        digest = RIPEMD160(string).digest()
    return digest

def ripemd160(string):
    return safe_hexlify(bin_ripemd160(string))

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def dbl_sha256(string):
    return safe_hexlify(bin_dbl_sha256(string))

def bin_slowsha(string):
    string = from_string_to_bytes(string)
    orig_input = string
    for i in range(100000):
        string = hashlib.sha256(string + orig_input).digest()
    return string

def slowsha(string):
    return safe_hexlify(bin_slowsha(string))

def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)

def num_to_var_int(x):
    x = int(x)
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253)+encode(x, 256, 2)[::-1]
    elif x < 4294967296: return from_int_to_byte(254) + encode(x, 256, 4)[::-1]
    else: return from_int_to_byte(255) + encode(x, 256, 8)[::-1]

# WTF, Electrum?
def electrum_sig_hash(message):
    padded = b"\x18Bitcoin Signed Message:\n" + num_to_var_int(len(message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)

def random_key():
    # Gotta be secure after that java.SecureRandom fiasco...
    entropy = random_string(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)

def random_electrum_seed():
    entropy = os.urandom(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)[:32]

# Encodings

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]


def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return ord(data[0])


def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)


def b58check_to_hex(inp):
    return safe_hexlify(b58check_to_bin(inp))

def pubkey_to_address(pubkey, magicbyte=0):
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address

def wif_compressed_privkey(priv,vbyte=0):
    return bin_to_b58check(binascii.unhexlify(priv), 128+int(vbyte))

#Note: these 2 functions require priv/pubkeys in binary not hex
def ecdsa_sign(msg, priv):
    #Compatibility issue: old bots will be confused
    #by different msg hashing algo; need to keep electrum_sig_hash, temporarily.
    hashed_msg = electrum_sig_hash(msg)
    dersig = ecdsa_raw_sign(hashed_msg, priv, False, rawmsg=True)
    #see comments to legacy* functions
    sig = legacy_ecdsa_sign_convert(dersig)
    return base64.b64encode(sig)

def ecdsa_verify(msg, sig, pub):
    #See note to ecdsa_sign
    hashed_msg = electrum_sig_hash(msg)
    sig = base64.b64decode(sig)
    #see comments to legacy* functions
    sig = legacy_ecdsa_verify_convert(sig)
    if not sig:
        return False
    return ecdsa_raw_verify(hashed_msg, pub, sig, False,rawmsg=True)

#A sadly necessary hack until all joinmarket bots are running secp256k1 code.
#pybitcointools *message* signatures (not transaction signatures) used an old signature
#format, basically: [27+y%2] || 32 byte r || 32 byte s,
#instead of DER. These two functions translate the new version into the old so that 
#counterparty bots can verify successfully.
def legacy_ecdsa_sign_convert(dersig):
    #note there is no sanity checking of DER format (e.g. leading length byte)
    dersig = dersig[2:] #e.g. 3045
    rlen = ord(dersig[1]) #ignore leading 02
    if rlen==32:
        r = dersig[2:34]
        ssig = dersig[34:]
    elif rlen==33:
        r = dersig[3:35] #leading 00 in canonical DER stripped
        ssig = dersig[35:]
    else:
        raise Exception("Incorrectly formatted DER sig:"+binascii.hexlify(dersig))
    slen = ord(ssig[1]) #ignore leading 02
    if slen==32:
        s = ssig[2:34]
    elif slen==33:
        s = ssig[3:35] #leading 00 in canonical DER stripped
    else:
        raise Exception("Incorrectly formatted DER sig:"+binascii.hexlify(dersig))
    #note: in the original pybitcointools implementation, 
    #verification ignored the leading byte (it's only needed for pubkey recovery)
    #so we just ignore parity here.
    return chr(27)+r+s

def legacy_ecdsa_verify_convert(sig):
    sig = sig[1:] #ignore parity byte
    try:
        r, s = sig[:32],sig[32:]
    except:
        #signature is invalid.
        return False
    if not len(s)==32:
        #signature is invalid.
        return False
    #canonicalize r and s
    for x in [r,s]:
        if ord(x[0])>127:
            x = '\x00'+x
    rlen = chr(len(r))
    slen = chr(len(s))
    total_len = 2+len(r)+2+len(s)
    return '\x30'+chr(total_len)+'\x02'+rlen+r+'\x02'+slen+s
