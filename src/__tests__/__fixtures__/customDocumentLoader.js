const fs = require("fs");
const path = require("path");

const contexts = {
  "https://w3id.org/did/v1": require("./contexts/did-v0.11.json"),
  "https://transmute-industries.github.io/linked-data-signature-starter-kit/contexts/linked-data-signature-starter-kit-v0.0.jsonld": JSON.parse(
    fs
      .readFileSync(
        path.resolve(
          __dirname,
          "../../../docs/contexts/linked-data-signature-starter-kit-v0.0.jsonld"
        )
      )
      .toString()
  )
};

const customLoader = url => {
  const context = contexts[url];

  if (context) {
    return {
      contextUrl: null, // this is for a context via a link header
      document: context, // this is the actual document that was loaded
      documentUrl: url // this is the actual context URL after redirects
    };
  }

  if (url === "did:example:123") {
    return {
      contextUrl: null, // this is for a context via a link header
      document: require("./contexts/didDoc.json"), // this is the actual document that was loaded
      documentUrl: url // this is the actual context URL after redirects
    };
  }
  console.error("No custom context support for " + url);
  throw new Error("No custom context support for " + url);
};

module.exports = customLoader;
