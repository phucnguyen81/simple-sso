const genJwtToken = payload => {
  const jwt = require("jsonwebtoken");
  const jwtValidatityKey = "simple-sso-jwt-validatity";
  const privateCert = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1haecO9shdFPg0hfndH5vAJfu7rrmQizIxCrY15rIep4b/Ae
+giQFo8H8MrTsuKlHAfx5Tb0yH7QR1k5VfTfBadI+XQUZR1gOdqqm47Qd/XlZbF6
YyzaAiwvh9PM12UjyEud6+XQOEkiD9Nh8RnZzHcR+15d+j1Rcx36KC2TismBe5Y/
LtGtUNkFoLfNokLPt44dOWlV5PeaSDZD6fTMVlH2GC09oFGDR4PYFNA0fdPZh5cw
5WLDyssItGbFMLjxPnw+IwvkT9jQedlwIrWIo1fAnHAEIzbfOsAXKjK+cwjw4gGA
lWznoaQdvNrxoOUy9lOjpdQmogK/Ws9P2h538wIDAQABAoIBAHac9Y+wtzm07A7a
jE9ORMULs6q5N0sEbOuikrJtX4Hc/HlYWnFBSUOWX1njpkLYG45aQIU0W46x5AeD
waaEEwR42I+M5rfW/LdRFXE2QP4VuNEM8bf845SMkpD4oec83ARfENHf8+sbacnG
3d7M6cTEu6u/buX0Dypuk2irR7F+Sz/kFuoIAmP9YzmhVhiRI9UwBIr4L31IgIiV
F3dtbguM6TJc4J604npW/iZqJ6Nt0dVhs2E0eO7tnaSkIrP2H40xOX939XYtPYPE
n0lTTl1tY0ds04kDHxnWn6SUNmiv6j4d0LLohBsjeEufYk+nq7yxaamsJlpBr6nh
Lk3oqCECgYEA+qvk3K5/odCitNtqN6uJFFDhXbaj5g4BdTlcBV0tJ9CUHDLHZZip
JY1lv+tXGNNkYC4pnHverHFnKnprgEz972EeJkxvDTRRoZ5tP3Sd1c8rIWfu+kYZ
XA1qX8EEvoatz+WLoUj5Thgc2TN94ykkQCjUjjnoUgkPMEoDfAXarosCgYEA2qOl
jGwNFsuqx5ARj4U4L2fx5np9KsN9BSsglCqTWLWp2dhE+2lobLxZZh2KqcbLxNnD
QDW9J/pudCiRj16K6bNl6gi3dL1Jl8nEd8M2HbxjU/i64yh+V4AJt4BHHs/QTMh0
zxd6+z58p2Ae9QIubmv+0f98xbt75mi1byCvMTkCgYBV9tseny0gBhe2ZESx4L66
293dsIPWolj3pXscT87rh4kzfmqJOehP+4S4Y3HUDrKulUYp5wT/KEjT9XWmY0D2
ddzMD4xJ//Y6scUPbOOv7kMBSs5Wv/F0cxlWyy/gUvmKgVL4Nblhgb1q81CptXM8
GYSDXfKBJ6Aw1EELqEpNbwKBgQCM241WUG6GVyRpeWm22w79i6wO3q8xE8zBva05
h8xyBGevD2QxzREXrKiz3yhshMTWx6zA+14oGXF7qH9OrIw2T/vCsWbv8NsuzTCk
L8H3ml0rxj0xB++Nk9GuxRgMw7nhHewTV39FylYoxwZqtsMPJMiApmbORSFnqeHp
/FaiEQKBgQDhKEnCZTQ/TjWjWyJr7AcdmV9NZpi967W4nioU1hfU65lR5KNzNwUG
iCEKtNwqK4QHK/KC4E2rEqU7DCCuun51Om39aMOsWto6yQRerz+2RSRKPxRvHoBT
6NaNYXOZtAxRidMw28o9CZWQwwig9VpsHy5+YwXcpXKYhrHLS+Tppg==
-----END RSA PRIVATE KEY-----
`;
  const ISSUER = "simple-sso";

  return new Promise((resolve, reject) => {
    // some of the libraries and libraries written in other language,
    // expect base64 encoded secrets, so sign using the base64 to make
    // jwt useable across all platform and langauage.
    jwt.sign(
      { ...payload },
      privateCert,
      {
        algorithm: "RS256",
        expiresIn: "1h",
        issuer: ISSUER
      },
      (err, token) => {
        if (err) return reject(err);
        return resolve(token);
      }
    );
  })
};

module.exports = Object.assign({}, { genJwtToken });
