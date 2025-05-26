# JWT Validator Library

Reusable Java library for validating JSON Web Tokens (JWT) with support for both symmetric and asymmetric signatures.

## Features

- Validate JWTs signed with HMAC (symmetric keys)
- Validate JWTs signed with RSA/ECDSA (asymmetric keys)
- Easy integration into Java applications
- Robust signature verification and claims validation

## Installation

Add the dependency via Maven Central:

```xml
<dependency>
  <groupId>io.github.kjistik</groupId>
  <artifactId>jwt-validator</artifactId>
  <version>1.1.0</version>
</dependency>
