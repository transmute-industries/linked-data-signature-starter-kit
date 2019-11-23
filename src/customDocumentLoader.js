const jsonld = require("jsonld");

const _nodejs =
  typeof process !== "undefined" && process.versions && process.versions.node;
const _browser =
  !_nodejs && (typeof window !== "undefined" || typeof self !== "undefined");

const documentLoader = _browser
  ? jsonld.documentLoaders.xhr()
  : jsonld.documentLoaders.node();

const contexts = {
  "https://w3id.org/did/v1": require("./contexts/did-v0.11.json"),
  "https://example.com/my-context/v2": require("./contexts/my-context.json"),
  "https://raw.githubusercontent.com/w3c/did-core/master/contexts/did-v0.11.jsonld": require("./contexts/did-v0.11.json")
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

  console.log(url);
  // const doc = await documentLoader(url);
  // return documentLoader(url, callback);
};

module.exports = customLoader;
