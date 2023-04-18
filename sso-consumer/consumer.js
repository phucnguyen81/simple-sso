const PORT = process.argv[2] || 3020;

const express = require("express");
const morgan = require("morgan");
const app = express();
const engine = require("ejs-mate");
const session = require("express-session");

/**
 * Given a token, use the public key to verify that the token comes
 * from the issuer simple-sso, i.e. the server has the private key
 * to sign the token.
 *
 * @param {string} token - the jwt token to verify
 * @returns a promise that resolves to the decoded token if the token is valid
 */
function verifyJwtToken(token) {
  const jwt = require("jsonwebtoken");

  const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1haecO9shdFPg0hfndH5
vAJfu7rrmQizIxCrY15rIep4b/Ae+giQFo8H8MrTsuKlHAfx5Tb0yH7QR1k5VfTf
BadI+XQUZR1gOdqqm47Qd/XlZbF6YyzaAiwvh9PM12UjyEud6+XQOEkiD9Nh8RnZ
zHcR+15d+j1Rcx36KC2TismBe5Y/LtGtUNkFoLfNokLPt44dOWlV5PeaSDZD6fTM
VlH2GC09oFGDR4PYFNA0fdPZh5cw5WLDyssItGbFMLjxPnw+IwvkT9jQedlwIrWI
o1fAnHAEIzbfOsAXKjK+cwjw4gGAlWznoaQdvNrxoOUy9lOjpdQmogK/Ws9P2h53
8wIDAQAB
-----END PUBLIC KEY-----
`
  const ISSUER = "simple-sso";

  console.log(`Use public key to verify that the JWT token comes from issuer ${ISSUER}`);
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      publicKey,
      { issuer: ISSUER, algorithms: ["RS256"] },
      (err, decoded) => {
        if (err) return reject(err);
        return resolve(decoded);
      }
    );
  });
}

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(morgan("dev"));
app.engine("ejs", engine);
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

app.use(
  async function(req, res, next) {
    const url = require("url");
    const axios = require("axios");
    const { URL } = url;
    const validReferOrigin = "http://sso.ankuranand.com:3010";
    const ssoServerJWTURL = "http://sso.ankuranand.com:3010/simplesso/verifytoken";

    // check if the req has the queryParameter as ssoToken
    // and who is the referer.
    const { ssoToken } = req.query;
    if (ssoToken != null) {
      console.log(`Receive sso token ${ssoToken} from sso server.`);
      // to remove the ssoToken in query parameter redirect.
      const redirectURL = url.parse(req.url).pathname;
      console.log(`After log in with sso server, will redirect to ${redirectURL}`);
      try {
        console.log('Verify the sso token with SSO Server using Authorization header');
        const response = await axios.get(
          `${ssoServerJWTURL}?ssoToken=${ssoToken}`,
          {
            headers: {
              Authorization: "Bearer l1Q7zkOL59cRqWBkQ12ZiGVW2DBL"
            }
          }
        );
        const { token } = response.data;
        console.log(`Received a JWT token from verifying the sso token ${ssoToken}`);
        const decoded = await verifyJwtToken(token);
        console.log(`Decoded credentials from JWT token ${token}:`, decoded);
        // Now that we have the decoded jwt, we can use the credentials
        // in the jwt to create the session user. We can use the
        // global-session-id in the token as the session id so that
        // the logout can be implemented with the global session.
        req.session.user = decoded;
      } catch (err) {
        return next(err);
      }

      return res.redirect(`${redirectURL}`);
    }

    return next();
  }
);

app.get("/", (req, res, next) => {
  // pass the redirect URL as current URL
  // serviceURL is where the sso should redirect in case of valid user
  const redirectURL = `${req.protocol}://${req.headers.host}${req.path}`;

  // simple check to see if the user is authenicated or not,
  // if not redirect the user to the SSO Server for Login
  if (req.session.user == null) {
    console.log(`No user session found, redirecting to SSO Server simplesso/login.`);
    console.log(`After log in to SSO server, will use serviceURL ${redirectURL} to redirect back to this app.`);
    return res.redirect(
      `http://sso.ankuranand.com:3010/simplesso/login?serviceURL=${redirectURL}`
    );
  }

  console.log(`User session found, rendering index page`);
  res.render("index", {
    what: `SSO-Consumer One ${JSON.stringify(req.session.user)}`,
    title: "SSO-Consumer | Home"
  });
});

app.use((req, res, next) => {
  // catch 404 and forward to error handler
  const err = new Error("Resource Not Found");
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  console.error({
    message: err.message,
    error: err
  });
  const statusCode = err.status || 500;
  let message = err.message || "Internal Server Error";

  if (statusCode === 500) {
    message = "Internal Server Error";
  }
  res.status(statusCode).json({ message });
});

app.listen(PORT, () => {
  console.info(`sso-consumer is listening on port ${PORT}`);
});
