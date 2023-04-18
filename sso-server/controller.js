const uuidv4 = require("uuid/v4");
const Hashids = require("hashids");
const URL = require("url").URL;
const jwt = require("jsonwebtoken");

const hashids = new Hashids();

/**
 * Generates a signed jwt token for a given a payload.
 *
 * @param {object} - the jwt token payload to be signed
 * @returns {Promise} - a promise that resolves to the jwt token
 */
function genJwtToken(payload) {
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

const re = /(\S+)\s+(\S+)/;

// Note: express http converts all headers to lower case
const AUTH_HEADER = "authorization";
const BEARER_AUTH_SCHEME = "bearer";

function parseAuthHeader(hdrValue) {
  if (typeof hdrValue !== "string") {
    return null;
  }
  const matches = hdrValue.match(re);
  return matches && { scheme: matches[1], value: matches[2] };
}

const fromAuthHeaderWithScheme = function(authScheme) {
  const authSchemeLower = authScheme.toLowerCase();
  return function(request) {
    let token = null;
    if (request.headers[AUTH_HEADER]) {
      const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
      if (authParams && authSchemeLower === authParams.scheme.toLowerCase()) {
        token = authParams.value;
      }
    }
    return token;
  };
};

const fromAuthHeaderAsBearerToken = function() {
  return fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

const appTokenFromRequest = fromAuthHeaderAsBearerToken();

// app token to validate the request is coming from the authenticated server only.
const appTokenDB = {
  sso_consumer: "l1Q7zkOL59cRqWBkQ12ZiGVW2DBL",
  simple_sso_consumer: "1g0jJwGmRQhJwvwNOrY4i90kD0m"
};

const alloweOrigin = {
  "http://consumer.ankuranand.in:3020": true,
  "http://consumertwo.ankuranand.in:3030": true,
  "http://sso.ankuranand.in:3080": false
};

const deHyphenatedUUID = () => uuidv4().replace(/-/gi, "");
const encodedId = () => hashids.encodeHex(deHyphenatedUUID());

// A temporary cahce to store all the application that has login using the current session.
// It can be useful for various audit purposes
const sessionUser = {};
const sessionApp = {};

const originAppName = {
  "http://consumer.ankuranand.in:3020": "sso_consumer",
  "http://consumertwo.ankuranand.in:3030": "simple_sso_consumer"
};

const userDB = {
  "info@ankuranand.com": {
    password: "test",
    userId: encodedId(),  // in case you don't want to share the user-email
    appPolicy: {
      sso_consumer: { role: "admin", shareEmail: true },
      simple_sso_consumer: { role: "user", shareEmail: false }
    }
  }
};

// these token are for the validation purpose
const intrmTokenCache = {};

const fillIntrmTokenCache = (origin, id, intrmToken) => {
  intrmTokenCache[intrmToken] = [id, originAppName[origin]];
};

const storeApplicationInCache = (origin, id, intrmToken) => {
  if (sessionApp[id] == null) {
    sessionApp[id] = {
      [originAppName[origin]]: true
    };
    fillIntrmTokenCache(origin, id, intrmToken);
  } else {
    sessionApp[id][originAppName[origin]] = true;
    fillIntrmTokenCache(origin, id, intrmToken);
  }
  console.log({ ...sessionApp }, { ...sessionUser }, { intrmTokenCache });
};

/**
 * Generate sso user's details to be shared with the application.
 * The application can take the sso user's details and log in
 * the corresponding user in the application.
 *
 * @param {string} ssoToken
 * @returns user details to be shared with the application
 */
const generatePayload = ssoToken => {
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  const appName = intrmTokenCache[ssoToken][1];
  const userEmail = sessionUser[globalSessionToken];
  const user = userDB[userEmail];
  const appPolicy = user.appPolicy[appName];
  const email = appPolicy.shareEmail === true ? userEmail : undefined;
  const payload = {
    ...{ ...appPolicy },
    ...{
      email,
      shareEmail: undefined,
      uid: user.userId,
      // global SessionID for the logout functionality.
      globalSessionID: globalSessionToken
    }
  };
  return payload;
};

const verifySsoToken = async (req, res, next) => {
  // The application token represents a application registered with the sso server
  const appToken = appTokenFromRequest(req);
  // The sso token represents a valid sso session created by the sso server
  const { ssoToken } = req.query;

  // At this point both the application token and sso token must be prrovided.
  if (
    appToken == null ||
    ssoToken == null ||
    intrmTokenCache[ssoToken] == null
  ) {
    return res.status(400).json({ message: "badRequest" });
  }

  // Also, both the application token and sso token must be valid.
  // This mean the application token must be registered with the sso server
  // and the sso token must be generated by the sso server.
  const appName = intrmTokenCache[ssoToken][1];
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  if (
    appToken !== appTokenDB[appName] ||
    sessionApp[globalSessionToken][appName] !== true
  ) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  // checking if the token passed has been generated
  const payload = generatePayload(ssoToken);

  const token = await genJwtToken(payload);
  // delete the itremCache key for no futher use,
  delete intrmTokenCache[ssoToken];
  return res.status(200).json({ token });
};

/**
 * The sso server does the login and redirect to the application.
 * The sso server does not give out the user credentials to the application
 * right away. It gives out a token which can be used to fetch the user.
 */
const doLogin = (req, res, next) => {
  // Validate email and password, hard coded for now.
  const { email, password } = req.body;
  if (!(userDB[email] && password === userDB[email].password)) {
    return res.status(404).json({ message: "Invalid email and password" });
  }

  // Email and password validated, create user session on sso server
  const id = encodedId();
  req.session.user = id;
  sessionUser[id] = email;

  // Without redirect url, go to sso home page
  const { serviceURL } = req.query;
  if (serviceURL == null) {
    return res.redirect("/");
  }

  // With redirect url, redirect to the consumer application
  // and provide an sso token to fetch more user credentials
  const url = new URL(serviceURL);
  const intrmid = encodedId();
  storeApplicationInCache(url.origin, id, intrmid);
  return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
};

/**
 * The consumer calls this to initialize the login flow with the SSO server.
 * If the user has not been logged in, the user will be redirected to the login page.
 */
const login = (req, res, next) => {
  // The req.query will have the redirect url where we need to redirect after successful
  // login and with sso token.
  // This can also be used to verify the origin from where the request has came in
  // for the redirection
  const { serviceURL } = req.query;

  // direct access will give the error inside new URL.
  if (serviceURL != null) {
    const url = new URL(serviceURL);

    // Allow sso login from certain origin urls only
    if (alloweOrigin[url.origin] !== true) {
      return res
        .status(400)
        .json({ message: `Your origin ${url.origin} are not allowed to access the sso-server` });
    }
  }

  // Already logged in without a redirect url, go to sso home page
  if (req.session.user != null && serviceURL == null) {
    return res.redirect("/");
  }

  // Already loggin in with a redirect url, redirect to the url and provide
  // an sso token for further retrival of sso user credentials
  if (req.session.user != null && serviceURL != null) {
    const url = new URL(serviceURL);
    const intrmid = encodedId();
    storeApplicationInCache(url.origin, req.session.user, intrmid);
    return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
  }

  // Else, user has not logged in sso server, show the sso login page
  return res.render("login", {
    title: "SSO-Server | Login"
  });
};

module.exports = Object.assign({}, { doLogin, login, verifySsoToken });
