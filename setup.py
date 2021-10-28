#!/usr/bin/env python3


# from distutils.core import setup, Extension
from setuptools import setup, Extension, find_packages
import os

def main():

    ext = Extension(
        name="ntru_wrap_c",
        sources=["src/ntru_wrap.c", "src/strtouint8ptr.c"],
        library_dirs=["lib"],
        include_dirs=["lib"],
        extra_objects=["lib/liboqs.a"],
    )

    setup(name="pqcc",
            version="0.0.1a0",
            description="Combination of Classical and Post-Quantum Symmetric and Asymmetric Encryption (RSA + NTRU + AES)",
            author="Christoph Winter",
            author_email="cheesemid@protonmail.com",
            package_dir={'': 'pqcc'},
            py_modules=["pqcc"],
            dependency_links=["git+https://github.com/cheesemid/keyops.git@main#egg=keyops"],
            install_requires=["keyops"],
            ext_modules=[ext])

if __name__ == "__main__":
    main()

