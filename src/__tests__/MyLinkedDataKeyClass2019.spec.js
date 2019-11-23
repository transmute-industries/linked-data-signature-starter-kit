const base64url = require("base64url");
const { MyLinkedDataKeyClass2019 } = require("../index");
const { publicKeyJwk, privateKeyJwk } = require("./__fixtures__");

const testBuffer = Buffer.from("123");

describe("MyLinkedDataKeyClass2019", () => {
  it("generate", async () => {
    let myLdKey = await MyLinkedDataKeyClass2019.generate("EC", "secp256k1");
    expect(myLdKey.privateKeyJwk).toBeDefined();
    expect(myLdKey.publicKeyJwk).toBeDefined();
  });

  it("sign", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk
    });

    const { sign } = myLdKey.signer();
    expect(typeof sign).toBe("function");
    const signature = await sign({ data: testBuffer });
    const [encodedHeader, encodedSignature] = signature.split("..");
    const header = JSON.parse(base64url.decode(encodedHeader));
    expect(header.kid).toBe(myLdKey.publicKeyJwk.kid);
    expect(header.b64).toBe(false);
    expect(header.crit).toEqual(["b64"]);
    expect(encodedSignature).toBeDefined();
  });

  it("verify", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk
    });
    const { verify } = myLdKey.verifier();
    expect(typeof verify).toBe("function");
    const signature =
      "eyJraWQiOiJKVXZwbGxNRVlVWjJqb081OVVOdWlfWFlEcXhWcWlGTExBSjhrbFd1UEJ3IiwiYjY0IjpmYWxzZSwiY3JpdCI6WyJiNjQiXSwiYWxnIjoiRVMyNTZLIn0..40BtGXu6bkXUD4ByQ1DHF2-EIzRJHvf2ZO_5e3W-YsrmN2XViPH0hbOoEgJOGdMz-hoyLqpxrA7foptxPVUIEA";
    const result = await verify({
      data: testBuffer,
      signature
    });
    expect(result).toBe(true);
  });

  it("generate, sign, verify", async () => {
    let myLdKey = await MyLinkedDataKeyClass2019.generate("EC", "secp256k1");
    const { verify } = myLdKey.verifier();
    const { sign } = myLdKey.signer();
    expect(typeof verify).toBe("function");
    const signature = await sign({ data: testBuffer });
    const result = await verify({
      data: testBuffer,
      signature
    });
    expect(result).toBe(true);
  });

  it("import keys, sign, verify", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk
    });
    const { verify } = myLdKey.verifier();
    const { sign } = myLdKey.signer();
    expect(typeof verify).toBe("function");
    const signature = await sign({ data: testBuffer });
    const result = await verify({
      data: testBuffer,
      signature
    });
    expect(result).toBe(true);
  });

  it("can create with controller and id", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk,
      id: "did:example:123#kid",
      controller: "did:example:123"
    });
    expect(myLdKey.id).toBe("did:example:123#kid");
    expect(myLdKey.controller).toBe("did:example:123");
  });

  it("publicKey / privateKey", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk,
      id: "did:example:123#kid",
      controller: "did:example:123"
    });
    expect(myLdKey.publicKey).toEqual(publicKeyJwk);
    expect(myLdKey.privateKey).toEqual(privateKeyJwk);
  });

  it("addEncodedPublicKey", async () => {
    const myLdKey = new MyLinkedDataKeyClass2019({
      publicKeyJwk,
      privateKeyJwk,
      id: "did:example:123#kid",
      controller: "did:example:123",
      type: "MyJwsVerificationKey2019"
    });
    const node = myLdKey.publicNode({
      controller: "did:example:456"
    });
    expect(node.id).toBe("did:example:123#kid");
  });
});
