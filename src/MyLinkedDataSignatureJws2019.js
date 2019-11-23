const EncodedLinkedDataSignature = require("./EncodedLinkedDataSignature");
const LDKeyClassJose = require("./LDKeyClassJose");

const linkedDataSignatureType = "MyLinkedDataSignatureJws2019";
const linkedDataVerificationKeyType = "MyJwsVerificationKey2019";
const linkedDataSignatureJoseAlg = "ES256K-R";

// const linkedDataSignatureType = "EcdsaSecp256k1Signature2019";
// const linkedDataVerificationKeyType = "EcdsaSecp256k1VerificationKey2019";
// const linkedDataSignatureJoseAlg = "ES256K";

module.exports = class MyLinkedDataSignatureJws2019 extends EncodedLinkedDataSignature {
  constructor({
    signer,
    key,
    creator,
    verificationMethod,
    proof,
    date,
    useNativeCanonize
  } = {}) {
    super({
      type: linkedDataSignatureType,
      alg: linkedDataSignatureJoseAlg,
      LDKeyClass: LDKeyClassJose,
      creator,
      verificationMethod,
      signer,
      key,
      proof,
      date,
      useNativeCanonize
    });
    this.requiredKeyType = linkedDataVerificationKeyType;
  }
};
