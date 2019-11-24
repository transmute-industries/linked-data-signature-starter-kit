const privateKeyJwk = {
  crv: "secp256k1",
  d: "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

const publicKeyJwk = {
  crv: "secp256k1",
  kid: "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
  kty: "EC",
  x: "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
  y: "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
};

const documentLoader = require("./customDocumentLoader");

const doc = {
  "@context": [
    "https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld",
    {
      schema: "http://schema.org/",
      name: "schema:name",
      homepage: "schema:url",
      image: "schema:image"
    }
  ],
  name: "Manu Sporny",
  homepage: "https://manu.sporny.org/",
  image: "https://manu.sporny.org/images/manu.png"
};

const authenticateMeActionDoc = {
  "@context": [
    "https://w3id.org/did/v1",
    {
      schema: "http://schema.org/",
      action: "schema:action"
    }
  ],
  action: "AuthenticateMe"
};

const didKeypair = {
  passphrase: null,
  id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  type: "Ed25519VerificationKey2018",
  privateKeyBase58:
    "55dKnusKVZjGK9rtTQgT3usTnALuChkzQpoksz4jES5G7AKMCpQCBt3azfko5oTMQD11gPxQ1bFRAYWSwcYSPdPV",
  publicKeyBase58: "25C16YaTbD96wAvdokKnTmD8ruWvYARDkc6nfNEA3L71"
};

const didKeyDoc = {
  "@context": "https://w3id.org/did/v1",
  id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  publicKey: [
    {
      id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      type: "Ed25519VerificationKey2018",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyBase58: "25C16YaTbD96wAvdokKnTmD8ruWvYARDkc6nfNEA3L71"
    }
  ],
  authentication: ["did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"],
  assertionMethod: ["did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"],
  capabilityDelegation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"
  ],
  capabilityInvocation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"
  ],
  keyAgreement: [
    {
      id:
        "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#zCDHgu3FAkC7ugAMPB7UMjMssNx6XXFnWFJXF6FYU98CLH",
      type: "X25519KeyAgreementKey2019",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyBase58: "DnyBg4MYpNdF4JQihynmCiC5hpiZh5tkQdx4QTfk1xE5"
    }
  ]
};

const didKeyDoc2 = {
  "@context": "https://w3id.org/did/v1",
  id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
  publicKey: [
    {
      id: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      type: "Ed25519VerificationKey2018",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyJwk: {
        crv: "Ed25519",
        x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
        kty: "OKP",
        kid: "my-kid"
      }
    }
  ],
  authentication: ["did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"],
  assertionMethod: ["did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"],
  capabilityDelegation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"
  ],
  capabilityInvocation: [
    "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP"
  ],
  keyAgreement: [
    {
      id:
        "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP#zCDHgu3FAkC7ugAMPB7UMjMssNx6XXFnWFJXF6FYU98CLH",
      type: "X25519KeyAgreementKey2019",
      controller: "did:key:z6MkfXT3gnptvkda3fmLVKHdJrm8gUnmx3faSd1iVeCAxYtP",
      publicKeyBase58: "DnyBg4MYpNdF4JQihynmCiC5hpiZh5tkQdx4QTfk1xE5"
    }
  ]
};

module.exports = {
  privateKeyJwk,
  publicKeyJwk,
  doc,
  didKeyDoc,
  didKeyDoc2,
  didKeypair,
  authenticateMeActionDoc,
  documentLoader
};
