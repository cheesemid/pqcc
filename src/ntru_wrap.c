#define OQS_ENABLE_KEM_ntru_hps2048509
#include <oqs/oqs.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Python.h>

#include "strtouint8ptr.h"

#define CURRDATE "102721"


// #define OQS_KEM_ntru_hps2048509_length_public_key 699
// #define OQS_KEM_ntru_hps2048509_length_secret_key 935
// #define OQS_KEM_ntru_hps2048509_length_ciphertext 699
// #define OQS_KEM_ntru_hps2048509_length_shared_secret 32

// struct Keypair {
//    uint8_t *pubkey;
//    uint8_t *privkey;
// };
// struct Cipher_and_Secret {
//     uint8_t *ciphertext;
//     uint8_t *shared_secret;
// };

// PyObject *rettuple = PyTuple_New(2);


struct Twouint8t {
    uint8_t *a;
    uint8_t *b;
};

struct Twouint8t create_imp(){
    uint8_t *p_pubkey = calloc(OQS_KEM_ntru_hps2048509_length_public_key, 1);
    uint8_t *p_privkey = calloc(OQS_KEM_ntru_hps2048509_length_secret_key, 1);
    struct Twouint8t pub_and_priv; 
    
    OQS_STATUS status = OQS_KEM_ntru_hps2048509_keypair(p_pubkey, p_privkey);
    if (status == OQS_ERROR){
        printf("OQS_ERROR : Keypair\n");
        pub_and_priv.a = NULL;
        pub_and_priv.b = NULL;
        return pub_and_priv;
    }

    pub_and_priv.a = p_pubkey;
    pub_and_priv.b = p_privkey;

    return pub_and_priv;

}

struct Twouint8t encaps_imp(uint8_t *p_pubkey){
    uint8_t *p_ciphertext = calloc(OQS_KEM_ntru_hps2048509_length_ciphertext, 1);
    uint8_t *p_shared_secret = calloc(OQS_KEM_ntru_hps2048509_length_shared_secret, 1);
    struct Twouint8t cipher_and_secret;

    OQS_STATUS status = OQS_KEM_ntru_hps2048509_encaps(p_ciphertext, p_shared_secret, p_pubkey);
    if (status == OQS_ERROR){
        printf("OQS_ERROR : Encaps\n");
        cipher_and_secret.a = NULL;
        cipher_and_secret.b = NULL;
        return cipher_and_secret;
    }

    cipher_and_secret.a = p_ciphertext;
    cipher_and_secret.b = p_shared_secret;

    return cipher_and_secret;
}

uint8_t *decaps_imp(uint8_t *p_ciphertext, uint8_t *p_privkey){
    uint8_t *p_shared_secret = calloc(OQS_KEM_ntru_hps2048509_length_shared_secret, 1);
    unsigned char *p_char_ciphertext = (unsigned char *) p_ciphertext;

    OQS_STATUS ret = OQS_KEM_ntru_hps2048509_decaps(p_shared_secret, p_char_ciphertext, p_privkey);
    if (ret == OQS_ERROR){
        printf("OQS_ERROR : Decaps\n");
        return NULL;
    }

    return p_shared_secret;

}

static PyObject *create(PyObject *self, PyObject *args){
    char *p_str_pubkey, *p_str_privkey;
    struct Twouint8t keypair = create_imp();
    p_str_pubkey = uint8ptrtostr(OQS_KEM_ntru_hps2048509_length_public_key, keypair.a);
    p_str_privkey = uint8ptrtostr(OQS_KEM_ntru_hps2048509_length_secret_key, keypair.b);
    return Py_BuildValue("ss", p_str_pubkey, p_str_privkey);
}

static PyObject *encaps(PyObject *self, PyObject *args){
    char *p_str_pubkey, *p_str_ciphertext, *p_str_shared_secret;
    uint8_t *p_pubkey;

    if(!PyArg_ParseTuple(args, "s", &p_str_pubkey)) {
        return NULL;
    }

    p_pubkey = strtouint8ptr(p_str_pubkey);
    struct Twouint8t cipher_and_secret = encaps_imp(p_pubkey);
    p_str_ciphertext = uint8ptrtostr(OQS_KEM_ntru_hps2048509_length_public_key, cipher_and_secret.a);
    p_str_shared_secret = uint8ptrtostr(OQS_KEM_ntru_hps2048509_length_shared_secret, cipher_and_secret.b);
    return Py_BuildValue("ss", p_str_ciphertext, p_str_shared_secret);
}

static PyObject *decaps(PyObject *self, PyObject *args){
    char *p_str_ciphertext, *p_str_privkey, *p_str_shared_secret;
    uint8_t *p_ciphertext, *p_privkey, *p_shared_secret;

    if(!PyArg_ParseTuple(args, "ss", &p_str_ciphertext, &p_str_privkey)) {
        return NULL;
    }

    p_ciphertext = strtouint8ptr(p_str_ciphertext);
    p_privkey = strtouint8ptr(p_str_privkey);
    p_shared_secret = decaps_imp(p_ciphertext, p_privkey);
    p_str_shared_secret = uint8ptrtostr(OQS_KEM_ntru_hps2048509_length_shared_secret, p_shared_secret);
    return Py_BuildValue("s", p_str_shared_secret);
}

static PyMethodDef ntru_wrap_c[] = {
    {"create", create, METH_VARARGS, "Create NTRU Keypair and return as hex strings (Public key, Private key)"},
    {"encaps", encaps, METH_VARARGS, "Create NTRU Shared Secret and Ciphertext and return as hex strings (Ciphertext, Secret)"},
    {"decaps", decaps, METH_VARARGS, "Get NTRU Shared Secret from Ciphertext and return as hex string"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ntru_wrap_module = {
    PyModuleDef_HEAD_INIT,
    "ntru_wrap_c",
    "Python Module that wraps the NTRU PQC Algorithm "CURRDATE,
    -1,
    ntru_wrap_c
};

PyMODINIT_FUNC PyInit_ntru_wrap_c(void) {
    return PyModule_Create(&ntru_wrap_module);
}

int main(int argc, char **argv){
    return 0;
}