const base64url = require("base64url");

const decodeBase64UrlToString = data => {
  return base64url.decode(data);
};
module.exports = {
  decodeBase64UrlToString
};
