# **Post Quantum Cypto Cocktail**
**NOTE: THIS PROJECT IS STILL IN ITS EARLY STAGES AND LIKELY CONTAINS BUGS**  
**NOT YET RECCOMENDED FOR PRODUCTION USE**

RSA + NTRU + AES  
Combination of Classical and Post-Quantum Symmetric and Asymmetric Encryption  

## **What is it?**

PQCC is a Python library which allows for easy use of classical and post-quantum cryptography. The library uses a user-defined communication channel to another machine using the same library in which classical and post-quantum asymmetric algorithms are used to set up symmetric encryption for further communications. Ideally, this mechanism would protect against brute-force attacks from classical and quantum computers, but since there is no post-quantum cryptographic algorithm that has recieved a NIST certification yet, the mechanism can only be guaranteed to be at least as secure as RSA and AES.

## **Requirements**

1. [Liboqs static library](https://github.com/open-quantum-safe/liboqs) (necessary for NTRU)
    - Requires OpenSSL >= 1.1.1 or flag `-DOQS_USE_OPENSSL=OFF` can be passed to `Cmake`
    - `Cmake` flag `-DOQS_MINIMAL_BUILD="OQS_ENABLE_KEM_ntru_hps2048509"` can be used to minimize the library size
2. Linux-based operating system (for now)

## **Installation**

1. Clone this Github repository
2. Compile liboqs separately and copy `liboqs.a` to `lib` directory
3. Run `python3 setup.py install`

## **Usage**

1. Define a Channel Class
    - This class must extend `Channel` as defined in `pqcc/pqcc.py`
    - It must override both `send()` and `recv()` functions
    - `send()` must accept any number of bytes and send them to the communication partner
    - `recv()` must accept any number of bytes from communication partner and return it as one `bytes` object (should block until recieve buffer is empty)

2. Set the channel custom channel to be used by PQCC through `set_channel_class()`
3. Call either `client_initialize()` or `server_initialize()`
    - `client_initialize()` will initiate a communication while `server_initialize()` will listen for a client to connect

4. Use the resulting `aes_secret` to continue communication over the channel
    - Encryption and decryption must be done manually (for now)
