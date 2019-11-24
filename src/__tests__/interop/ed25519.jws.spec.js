const jose = require("@panva/jose");

describe("ed25519.jws", () => {
  it("sign and verify", async () => {
    const privateKeyJwk = {
      crv: "Ed25519",
      x: "D-5zI9uCYOAk_bN_QWD2XAQ_gIyHUh-6OY7nVk-Rg0g",
      d: "zA65gfNF5g2CLKQnl8uRbGI2IRjJIE7PTZki7Qin9bw",
      kty: "OKP",
      kid: "my-kid"
    };
    const header = {
      alg: "EdDSA",
      b64: false,
      crit: ["b64"]
    };
    const toBeSigned = Buffer.from("123");
    const flat = jose.JWS.sign.flattened(
      toBeSigned,
      jose.JWK.asKey(privateKeyJwk),
      header
    );
    const jws = `${flat.protected}..${flat.signature}`;
    expect(jws).toBe(
      "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..cugOFF6h7Dkqt9kM0IH8KA0_lnJO3rRbXrQOpsyQA-9NKMLISq0DZsMLN4iFtH_Rd6kDqa-1cDHuyNQV4ikfDA"
    );
    // const result = jose.JWS.verify(jws, jose.JWK.asKey(privateKeyJwk), {
    //   crit: ["b64"]
    // });
    // expect(result).toBe("123");
  });
});
