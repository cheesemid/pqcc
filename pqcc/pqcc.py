#!/usr/bin/env python3

import keyops
import ntru_wrap_c
import struct
import signal
from typing import Type
import time
import os
import sys

thismodule = sys.modules[__name__]

version = "0.0.1a"
user_channel = None
do_debug = True

retry_delay = .1
communication_timeout = 5

# Keys
rsa_pub = None
rsa_priv = None
rsa_pub_b = None

ntru_pub = None
ntru_priv = None
ntru_pub_b = None

ntru_pub_wrapped_rsa = None

aes_secret = None
aes_secret_ntru_cipher = None
aes_secret_rsa_ntru_cipher = None

# setattr(thismodule, "create", ntru_wrap_c.create)
# setattr(thismodule, "encaps", ntru_wrap_c.encaps)
# setattr(thismodule, "decaps", ntru_wrap_c.decaps)

class Channel:

    def __init__(self):
        self.channel_initialized = False

    def send(self, data: bytes=None) -> bool:
        raise Exception("send() has not been implemented in the Channel class")

    def recv(self) -> bytes:
        raise Exception("recv() has not been implemented in the Channel class")


class timeout: # From vmarquet on StackOverflow copied on 08/11/2021 : https://stackoverflow.com/a/22348885/8419873
    def __init__(self, seconds=1, error_message='Timeout', raise_exception=False):
        self.seconds = seconds
        self.error_message = error_message
        self.raise_exception = raise_exception

    def handle_timeout(self, signum, frame):
        if self.raise_exception:
            raise TimeoutError(self.error_message)

        print(self.error_message)
        return False

    def __enter__(self):
        # pylint: disable=no-member
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        # pylint: disable=no-member
        signal.alarm(0)


def debug_logger(msg):
    if do_debug:
        print(msg)

def set_channel_class(c: Type[Channel]):
    # Get channel subclass from user that implements send() and recv()
    global user_channel
    user_channel = c

def hton(data: bytes) -> bytes: # host to network byte order (just to make sure even though its not needed)
    return struct.unpack(f"!{len(data)}s", data)

def ntoh(data: bytes) -> bytes: # network to host byte order (just to make sure even though its not needed)
    return struct.pack(f"!{len(data)}s", data)
    

def client_initialize():
    global rsa_pub, rsa_priv, rsa_pub_b, ntru_pub, ntru_priv, ntru_pub_b, ntru_pub_wrapped_rsa, aes_secret, aes_secret_ntru_cipher, aes_secret_rsa_ntru_cipher

    # Simple Hello and Version Check
    while True:
        time.sleep(retry_delay)
        with timeout(seconds=communication_timeout, error_message="Hello and Version Check Timeout... Retrying"):
            user_channel.send(hton(b"PQCC v" + version.encode("ascii")))
            resp = ntoh(user_channel.recv())
            debug_logger("Hello and Version messages exchanged")
            continue

        if resp[:6] == b"PQCC v":
            debug_logger(f"Server is running PQCC v{resp[6:].decode('ascii')}")
        else:
            print(f"Server response incorrect... Retrying: {resp}")
            continue

    # Init RSA
        # Gen or Get RSA Keys
        if os.path.exists("rsa.pub") and os.path.exists("rsa.priv"):
            rsa_pub = keyops.rsa_key_ops.loadpub("rsa.pub")
        else:
            rsa_priv = keyops.rsa_key_ops.create(keysize=8192)
            rsa_pub = rsa_priv.public_key()
            # Save Keys to local directory
            keyops.rsa_key_ops.savepub(rsa_pub, "rsa.pub")
            keyops.rsa_key_ops.savepub(rsa_priv, "rsa.priv")

        # Exchange RSA Pubs
        user_channel.send(hton(keyops.rsa_key_ops.strpub(rsa_pub).encode("utf-8")))
        try:
            rsa_pub_b = keyops.rsa_key_ops.loadpubfromstr(ntoh(user_channel.recv()).decode("utf-8"))
        except ValueError: # Check for expected values
            debug_logger(f"Server RSA Key invalid")
            return 1
        
    
    # Init NTRU
        # Gen or Get NTRU Keys
        if os.path.exists("ntru.pub") and os.path.exists("ntru.priv"):
            with open("ntru.pub", "r") as infd:
                ntru_pub = infd.read()
            with open("ntru.priv", "r") as infd:
                ntru_priv = infd.read()
        else:
            ntru_pub, ntru_priv = ntru_wrap_c.create()
        # Wrap NTRU Pub in RSA Encryption with RSA Sig on outside
        encrypted = keyops.rsa_key_ops.encrypt(ntru_pub, rsa_pub_b) # 1024B length
        signed = keyops.rsa_key_ops.sign(encrypted, rsa_priv, returnhex=False) # 1024B length

        ntru_pub_wrapped_rsa = encrypted + signed # 2048B length

        # Send NTRU Pub wrapped with RSA to other machine
        user_channel.send(hton(ntru_pub_wrapped_rsa))

        # Get NTRU Wrapped from other machine
        ntru_pub_wrapped_rsa_b = ntoh(user_channel.recv())
        rsa_ntru_pub_b = ntru_pub_wrapped_rsa_b[:1024]
        rsa_ntru_sig_b = ntru_pub_wrapped_rsa_b[1024:]

        if keyops.rsa_key_ops.verify(rsa_ntru_pub_b, rsa_ntru_sig_b, rsa_pub_b):
            ntru_pub_b = keyops.rsa_key_ops.decrypt(rsa_ntru_pub_b, rsa_priv).decode("utf-8")
        else:
            debug_logger(f"Server RSA Signature on NTRU Pub invalid")
            return 1


    # Init AES
        aes_secret_ntru_cipher, aes_secret = ntru_wrap_c.encaps(ntru_pub_b)

        # Send RSA-NTRU Message with 256b key
        encrypted = keyops.rsa_key_ops.encrypt(aes_secret_ntru_cipher.encode("utf-8"), rsa_pub_b)
        signed = keyops.rsa_key_ops.sign(encrypted, rsa_priv, returnhex=False)

        aes_secret_rsa_ntru_cipher = encrypted + signed # 2048B length

        user_channel.send(hton(aes_secret_rsa_ntru_cipher))

        # Recieve Encrypted RND String and send reversed string encrypted to verify channel
        test_encryption_str = ntoh(user_channel.recv())
        test_str = keyops.aes_key_ops.decrypt(test_encryption_str[16:], test_encryption_str[:16], aes_secret)

        test_encryption_str_ret_cipher, test_encryption_str_ret_iv = keyops.aes_key_ops.encrypt(test_str[::-1], aes_secret)

        test_encryption_str_ret = test_encryption_str_ret_iv + test_encryption_str_ret_cipher

        user_channel.send(hton(test_encryption_str_ret))

        # Channel has been successfully set up
        # Messages sent with the channel must be manually encrypted and decrypted (Preferrably with aes_secret)
        return 0

def server_initialize():
    global rsa_pub, rsa_priv, rsa_pub_b, ntru_pub, ntru_priv, ntru_pub_b, ntru_pub_wrapped_rsa, aes_secret, aes_secret_ntru_cipher, aes_secret_rsa_ntru_cipher

    # Simple Hello and Version Check
    resp = ntoh(user_channel.recv())
    user_channel.send(hton(b"PQCC v" + version.encode("ascii")))
    debug_logger("Hello and Version messages exchanged")

    if resp[:6] == b"PQCC v":
        debug_logger(f"Client is running PQCC v{resp[6:].decode('ascii')}")
    else:
        print(f"Client response incorrect... Exiting: {resp}")
        return 1

    # Init RSA
        # Gen or Get RSA Keys
        if os.path.exists("rsa.pub") and os.path.exists("rsa.priv"):
            rsa_pub = keyops.rsa_key_ops.loadpub("rsa.pub")
        else:
            rsa_priv = keyops.rsa_key_ops.create(keysize=8192)
            rsa_pub = rsa_priv.public_key()
            # Save Keys to local directory
            keyops.rsa_key_ops.savepub(rsa_pub, "rsa.pub")
            keyops.rsa_key_ops.savepub(rsa_priv, "rsa.priv")

        # Exchange RSA Pubs
        try:
            rsa_pub_b = keyops.rsa_key_ops.loadpubfromstr(ntoh(user_channel.recv()).decode("utf-8"))
        except ValueError: # Check for expected values
            debug_logger(f"Client RSA Key invalid")
            return 1
        user_channel.send(hton(keyops.rsa_key_ops.strpub(rsa_pub).encode("utf-8")))
        
        
    
    # Init NTRU
        # Gen or Get NTRU Keys
        if os.path.exists("ntru.pub") and os.path.exists("ntru.priv"):
            with open("ntru.pub", "r") as infd:
                ntru_pub = infd.read()
            with open("ntru.priv", "r") as infd:
                ntru_priv = infd.read()
        else:
            ntru_pub, ntru_priv = ntru_wrap_c.create()
        # Wrap NTRU Pub in RSA Encryption with RSA Sig on outside
        encrypted = keyops.rsa_key_ops.encrypt(ntru_pub, rsa_pub_b) # 1024B length
        signed = keyops.rsa_key_ops.sign(encrypted, rsa_priv, returnhex=False) # 1024B length

        ntru_pub_wrapped_rsa = encrypted + signed # 2048B length

        # Get NTRU Wrapped from other machine
        ntru_pub_wrapped_rsa_b = ntoh(user_channel.recv())
        rsa_ntru_pub_b = ntru_pub_wrapped_rsa_b[:1024]
        rsa_ntru_sig_b = ntru_pub_wrapped_rsa_b[1024:]

        if keyops.rsa_key_ops.verify(rsa_ntru_pub_b, rsa_ntru_sig_b, rsa_pub_b):
            ntru_pub_b = keyops.rsa_key_ops.decrypt(rsa_ntru_pub_b, rsa_priv).decode("utf-8")
        else:
            debug_logger(f"Server RSA Signature on NTRU Pub invalid")
            return 1

        # Send NTRU Pub wrapped with RSA to other machine
        user_channel.send(hton(ntru_pub_wrapped_rsa))


    # Init AES
        # Recieve RSA-NTRU Message with 256b key
        aes_secret_rsa_ntru_cipher = ntoh(user_channel.recv())
        aes_secret_rsa_ntru_sig = aes_secret_rsa_ntru_cipher[1024:]
        aes_secret_rsa_ntru_cipher = aes_secret_rsa_ntru_cipher[:1024]

        if keyops.rsa_key_ops.verify(aes_secret_rsa_ntru_cipher, aes_secret_rsa_ntru_sig, rsa_pub_b):
            aes_secret = ntru_wrap_c.decaps(keyops.rsa_key_ops.decrypt(aes_secret_rsa_ntru_cipher, rsa_priv), ntru_priv)

        # Send Encrypted RND String and send reversed string encrypted to verify channel
        rand_bytes = os.urandom(64)

        test_encryption_str_cipher, test_encryption_str_iv = keyops.aes_key_ops.encrypt(rand_bytes, aes_secret)
        test_encryption_str = test_encryption_str_iv + test_encryption_str_cipher
        user_channel.send(hton(test_encryption_str))

        test_encryption_str_ret = ntoh(user_channel.recv())

        test_encryption_str_ret_iv = test_encryption_str_ret[:16]
        test_encryption_str_ret_cipher = test_encryption_str_ret[16:]

        test_encryption_str_ret_reversed = keyops.aes_key_ops.decrypt(test_encryption_str_ret_cipher, test_encryption_str_ret_iv, aes_secret)

        if test_encryption_str_ret_reversed != rand_bytes[::-1]:
            debug_logger("Test Bytes were not properly reversed")
            return 1
            

        # Channel has been successfully set up
        # Messages sent with the channel must be manually encrypted and decrypted (Preferrably with aes_secret)
        return 0


