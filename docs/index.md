# Linked Data Signature Starter Kit

- [Latest JSON-LD Context](./contexts/linked-data-signature-starter-kit-v0.0.jsonld)

### Terminology

<h4 id="publicKeyJwk"><a href="#publicKeyJwk">publicKeyJwk</a></h4>

A public key in JWK format. A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. Read [RFC7517](https://tools.ietf.org/html/rfc7517).

#### Example:

```json
{
  "@context": "https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld",
  "id": "did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  "type": "MyJwsVerificationKey2019",
  "publicKeyJwk": {
    "crv": "secp256k1",
    "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
    "kty": "EC",
    "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
    "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
  }
}
```

<h4 id="MyJwsVerificationKey2019"><a href="#MyJwsVerificationKey2019">MyJwsVerificationKey2019</a></h4>

The verification key type for `MyLinkedDataSignature2019`. The key must have a property `publicKeyJwk` and its value must be a valid JWK.

#### Example:

```json
[
  {
    "@context": "https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld",
    "id": "did:example:123#JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
    "type": "MyJwsVerificationKey2019",
    "publicKeyJwk": {
      "crv": "secp256k1",
      "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
      "kty": "EC",
      "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
      "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
    }
  }
]
```

<h4 id="MyLinkedDataSignature2019"><a href="#MyLinkedDataSignature2019">MyLinkedDataSignature2019</a></h4>

A JSON-LD Document has been signed with MyLinkedDataSignature2019,
when it contains a proof field with type `MyLinkedDataSignature2019`. The proof must contain a key `jws` with value defined by the signing algorithm described here.

#### Example:

```json
{
  "@context": "https://w3id.org/security/v2",
  "http://schema.org/action": "AuthenticateMe",
  "proof": {
    "challenge": "abc",
    "created": "2019-01-16T20:13:10Z",
    "domain": "example.com",
    "proofPurpose": "authentication",
    "verificationMethod": "https://example.com/i/alice/keys/2",
    "type": "MyLinkedDataSignature2019",
    "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..QgbRWT8w1LJet_KFofNfz_TVs27z4pwdPwUHhXYUaFlKicBQp6U1H5Kx-mST6uFvIyOqrYTJifDijZbtAfi0MA"
  }
}
```
