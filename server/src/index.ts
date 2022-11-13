import express from "express";
import jwt from "jsonwebtoken";
import axios from "axios";
import cors from "cors";
import querystring from "querystring";
import cookieParser from "cookie-parser";
import {
  SERVER_ROOT_URI,
  GOOGLE_CLIENT_ID,
  JWT_SECRET,
  GOOGLE_CLIENT_SECRET,
  COOKIE_NAME,
  UI_ROOT_URI,
  GOOGLE_AUTH_URI,
  GOOGLE_TOKEN_URI,
  GOOGLE_USERINFO_BASE_URI,
} from "./config";

const port = 4000;

const app = express();

app.use(
  cors({
    // Sets Access-Control-Allow-Origin to the UI URI
    origin: UI_ROOT_URI,
    // Sets Access-Control-Allow-Credentials to true
    credentials: true,
  })
);

app.use(cookieParser());

const redirectURI = "auth/google";

function getGoogleAuthURL() {
  const rootUrl = GOOGLE_AUTH_URI;
  const options = {
    redirect_uri: `${SERVER_ROOT_URI}/${redirectURI}`,
    client_id: GOOGLE_CLIENT_ID,
    access_type: "offline",
    response_type: "code",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"].join(" "),
  };

  return `${rootUrl}?${querystring.stringify(options)}`;
}

// Getting login URL
app.get("/auth/google/url", (req, res) => {
  console.log("called", "/auth/google/url");
  return res.send(getGoogleAuthURL());
});

async function getTokens({ code, clientId, clientSecret, redirectUri }: { code: string; clientId: string; clientSecret: string; redirectUri: string }): Promise<{
  access_token: string;
  expires_in: Number;
  refresh_token: string;
  scope: string;
  id_token: string;
}> {
  /*
   * Uses the code to get tokens
   * that can be used to fetch the user's profile
   */
  const values = {
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  };

  try {
    const res = await axios.post(GOOGLE_TOKEN_URI, querystring.stringify(values), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    return res.data;
  } catch (error: any) {
    console.error(`Failed to fetch auth tokens`);
    throw new Error(error.message);
  }
}

// Getting the user from Google with the code
app.get(`/${redirectURI}`, async (req, res) => {
  console.log("called", redirectURI);
  const code = req.query.code as string;

  const { id_token, access_token } = await getTokens({
    code,
    clientId: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    redirectUri: `${SERVER_ROOT_URI}/${redirectURI}`,
  });

  // Fetch the user's profile with the access token and bearer
  const googleUser = await axios
    .get(`${GOOGLE_USERINFO_BASE_URI}?alt=json&access_token=${access_token}`, {
      headers: {
        Authorization: `Bearer ${id_token}`,
      },
    })
    .then((res) => res.data)
    .catch((error) => {
      console.error(`Failed to fetch user`);
      throw new Error(error.message);
    });

  console.log("googleUser", googleUser);

  const token = jwt.sign(googleUser, JWT_SECRET);

  res.cookie(COOKIE_NAME, token, {
    maxAge: 900000,
    httpOnly: true,
    secure: false,
  });

  res.redirect(UI_ROOT_URI);
});

// Getting the current user
app.get("/auth/me", (req, res) => {
  console.log("called", "get me");
  try {
    const decoded = jwt.verify(req.cookies[COOKIE_NAME], JWT_SECRET);
    console.log("decoded", decoded);
    return res.send(decoded);
  } catch (err) {
    console.log(err);
    res.send(null);
  }
});

function main() {
  app.listen(port, () => {
    console.log(`App listening http://localhost:${port}`);
  });
}

main();
