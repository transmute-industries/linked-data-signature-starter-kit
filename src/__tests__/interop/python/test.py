from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto.common import json_decode, json_encode


publicKey = {
    "crv": 'Ed25519',
    "x": 'h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw',
    "kty": 'OKP',
    "kid": '8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q'
}

privateKey = {
    "crv": 'Ed25519',
    "x": 'h83ufcOAO9zVigHCgOOTp8waN_ycH4xnPRvn45yu6gw',
    "d": 'Mqr_E4EQ51DxzVHh74HEy6F0JIykqDnrwgeJOxiLeTU',
    "kty": 'OKP',
    "kid": '8R_gUPjBoJ_nf39_G7VLGWNuhL5etuW7zvS46kwYN6Q'}


header = {
    "alg": "EdDSA",
    "b64": True,
    "crit": ["b64"]
}
payload = {"hello": 1}

s = jws.JWS(json_encode(payload))
s.add_signature(jwk.JWK.from_json(json_encode(privateKey)),
                'EdDSA', json_encode(header))

jws = s.serialize(compact=True)
# sig = s.sign()

print(jws)
# eyJhbGciOiJFZERTQSIsImI2NCI6dHJ1ZSwiY3JpdCI6WyJiNjQiXX0.eyJoZWxsbyI6MX0.d1SRP9BpMrflp4jx-T8JZnFpat47VDp3hU6EIt6tBrWwKBZpGkhETYaB3d1OZZFVJZy6KszwMi6DKDmzb3puDQ
# eyJhbGciOiJFZERTQSIsImI2NCI6dHJ1ZSwiY3JpdCI6WyJiNjQiXX0.eyJoZWxsbyI6MX0.d1SRP9BpMrflp4jx-T8JZnFpat47VDp3hU6EIt6tBrWwKBZpGkhETYaB3d1OZZFVJZy6KszwMi6DKDmzb3puDQ
