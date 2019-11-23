const jose = require("@panva/jose");
const base64url = require("base64url");
const LDKeyClassJose = require("./LDKeyClassJose");

const testBuffer = Buffer.from("123");

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

describe.skip("LDKeyClassJose", () => {
  it("generate", async () => {
    let ldKeyJose = await LDKeyClassJose.generate("EC", "secp256k1");
    expect(ldKeyJose.privateKeyJwk).toBeDefined();
    expect(ldKeyJose.publicKeyJwk).toBeDefined();
  });

  it("sign", async () => {
    const ldKeyJose = new LDKeyClassJose({
      publicKeyJwk,
      privateKeyJwk
    });

    const { sign } = ldKeyJose.signer();
    expect(typeof sign).toBe("function");
    const signature = await sign({ data: testBuffer });
    const [encodedHeader, encodedSignature] = signature.split("..");
    const header = JSON.parse(base64url.decode(encodedHeader));
    expect(header.kid).toBe(ldKeyJose.publicKeyJwk.kid);
    expect(header.b64).toBe(false);
    expect(header.crit).toEqual(["b64"]);
    expect(encodedSignature).toBeDefined();
  });

  it("verify", async () => {
    const ldKeyJose = new LDKeyClassJose({
      publicKeyJwk,
      privateKeyJwk
    });
    const { verify } = ldKeyJose.verifier();
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
    let ldKeyJose = await LDKeyClassJose.generate("EC", "secp256k1");
    const { verify } = ldKeyJose.verifier();
    const { sign } = ldKeyJose.signer();
    expect(typeof verify).toBe("function");
    const signature = await sign({ data: testBuffer });
    const result = await verify({
      data: testBuffer,
      signature
    });
    expect(result).toBe(true);
  });

  it("import keys, sign, verify", async () => {
    const ldKeyJose = new LDKeyClassJose({
      publicKeyJwk,
      privateKeyJwk
    });
    const { verify } = ldKeyJose.verifier();
    const { sign } = ldKeyJose.signer();
    expect(typeof verify).toBe("function");
    const signature = await sign({ data: testBuffer });
    const result = await verify({
      data: testBuffer,
      signature
    });
    expect(result).toBe(true);
  });
});
