# Formal Verification of ChaCha20-Poly1305 in OpenSSL
This is the source code repo for our project, which conducts the equvalence verfication of ChaCha20-Poly1305：
1) described in the standard (RFC 8439), and
2) implemented in the OpenSSL (v3.0.10).

This instruction describes the organization of the source code and how to use it.

## Software Requirements
- To run the RFC and OpenSSL Cryptol formal model of TLS 1.3 state machine you need [cryptol 3.1.0+](https://cryptol.net/).
- To verify equivalence between the OpenSSL formal model and the C code implementations, you need [SAW](https://saw.galois.com/).

## File Organization
**Source code files**:

- ChaCha20 Model, in the directory ``chacha20/``
  - ``chacha.c``  : Defined the source code of ChaCha20 algorithm in OpenSSL
  - ``chacha.bc`` : Compiled bytecode from OpenSSL ChaCha20 algorithm source code
  - ``chacha_openssl.cry`` :  Defined the ChaCha20 Cryptol model based on OpneSSL source code
  - ``chacha_rfc.cry`` : Defined the ChaCha20 Cryptol model based on RFC standard document 
  - ``chacha.saw``: The script for verifying the equvalence between OpenSSL Cryptol models and ChaCha20 C code implementations
  - ``chacha_property.cry``: Proved the ChaCha20 equvalence and some security properties between the Cryptol model based on OpenSSL and the Cryptol model based on standard documentation
- Poly1305  Model,  in the directory ``poly1305/``
  - ``poly.c``  : Defined the source code of Poly1305 algorithm in OpenSSL
  - ``poly.bc`` : Compiled bytecode from OpenSSL Poly1305 algorithm source code
  - ``poly64.c``  : Defined the source code for the 64 bit OpenSSL Poly1305 algorithm
  - ``poly64.bc`` :  Bytecode compiled from the 64 bit OpenSSL Poly1305 algorithm source code
  - ``poly.cry`` :  Defined the Poly1305 Cryptol model based on OpneSSL source code
  - ``poly64.cry`` :  Defined the Poly1305 Cryptol model based on 64 bit OpneSSL source code
  - ``poly_rfc.cry`` : Defined the Poly1305 Cryptol model based on RFC standard document 
  - ``poly.saw``: The script for verifying the equvalence between OpenSSL Cryptol models and Poly1305 C code implementations
  - ``poly_property.cry``: Proved the Poly1305 equvalence and some security properties between the Cryptol model based on OpenSSL and the Cryptol model based on standard documentation

## The Execution of RFC Model Alone
You can use the following commands to run the RFC Cryptol model once in the console for revision and testing.

```
PROJECTROOTDIR> cd chacha20 / cd poly1305
PROJECTROOTDIR/chacha20> Cryptol
PROJECTROOTDIR/RFC_Model> :l chacha_rfc.cry / :l poly_rfc.cry
```

## The Execution of OpenSSL Model Alone
You can use the following commands to run the OpenSSL Cryptol model once in the console for revision and testing.

```
PROJECTROOTDIR> cd chacha20 / cd poly1305
PROJECTROOTDIR/chacha20> Cryptol
PROJECTROOTDIR/RFC_Model> :l chacha_openssl.cry / :l poly.cry / :l poly64.cry
```

## The Execution of SAW
You can use the following commands to run the SAWScript to verify the equvalence between OpenSSL formal models and C code implementations, and output the results to the terminal.
```
PROJECTROOTDIR> cd chacha20 / cd poly1305
PROJECTROOTDIR/saw> saw [filename].saw
```
