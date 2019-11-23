# Linked Data Signature Starter Kit

The purpose of this repo is to provide a starting point for developers wishing to implement JSON-LD Signatures.

## Getting Started

```
npm i
npm run test
npm run coverage
```

You will need to implement 2 classes to create new JSON-LD Signature.

First, the `LinkedDataKeyClass`, we provide an example `MyLinkedDataKeyClass2019` that provides support for JOSE keys.

This class must support sign and verify interfaces, and SHOULD handle encoding of both key formats and signatures.

Second, the `LinkedDataSignature`, we provide an example `MyLinkedDataSignature2019` that supports creating JWS / JWK based JSON-LD Signatures.

A JSON-LD Signature has a verification key type, and a signature/proof type for example:

- `MyJwsVerificationKey2019`
- `MyLinkedDataSignature2019`

You must provide both a json-ld context, and human readable documentation for every property you create for your signature suite.

In this case, we define these verification key and proof formats, as well as the `publicKeyJwk` property.

You can read the documentation here:

[https://transmute-industries.github.io/linked-data-signature-starter-kit/](https://transmute-industries.github.io/linked-data-signature-starter-kit/)

And the context:

[https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld](https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld)

You MUST always version context files, and MUST ensure they remain resolvable at their published path once they are in use.

Failure to do so is similar to not maintaining an npm module, or unpublishing a module that may be used by others. If you are not sure if you can maintain a JSON-LD context, its best that you not create one, or rely on github / community structures to ensure that the context can easily be updated.

## License

These examples are meant to be used with https://github.com/digitalbazaar/jsonld-signatures
