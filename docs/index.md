#### [View on GitHub](https://github.com/transmute-industries/linked-data-signature-starter-kit)

> JSON-LD 1.1 is being formally specified in the W3C JSON-LD Working Group. To participate in this work, please join the W3C and then [join the Working Group](https://www.w3.org/2018/json-ld-wg/).

You can use this repo as a guide for extending contexts, and ensuring that your JSON-LD is functioning as expected and fully documented. This should help you make the case that your extensions should be included, or eliminate the need for them to be included.

- [Latest Starter Kit JSON-LD Context](./contexts/linked-data-signature-starter-kit-v0.0.jsonld)

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
    "crv": "Ed25519",
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
      "crv": "Ed25519",
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
