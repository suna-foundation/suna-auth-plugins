import "@nobush/server-only";
import axios from "axios";

import { Provider, Session, SessionType, UserType, AccountType, IWebRequest } from "suna-auth/dist/types";
import {
  Auth,
  createToken,
  decodeToken,
  sendErrorRedirect,
  sendJson,
} from "suna-auth";

interface Config {
  client_id: string;
  client_secret: string;
  scopes: string[];
  api_url?: string;
}

interface GoogleUserData {
  id: string;
  email: string;
  verified_email: boolean;
  picture: string;
}

interface GoogleTokenData {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  token_type: string;
  id_token: string;
}

export class GoogleProvider implements Provider {
  private static instance: GoogleProvider | null = null;
  name: "google" = "google";
  public credential: Config;

  private constructor(credential: Config) {
    this.credential = credential;
  }

  public static getInstance(config: Config): GoogleProvider {
    if (!this.instance) {
      this.instance = new GoogleProvider(config);
    }
    return this.instance;
  }

  public async handleCallback(request: IWebRequest) {
    const searchQuery = request.query;
    const code = searchQuery.get("code");
    if (!code) return sendErrorRedirect(400, "no ?code provided");

    const data = new URLSearchParams();
    data.append("code", code);
    data.append("client_id", this.credential.client_id);
    data.append("client_secret", this.credential.client_secret);
    data.append("redirect_uri", this.getRedirectUri());
    data.append("grant_type", "authorization_code");

    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      data,
      {
        validateStatus: () => true,
      },
    );
    const tokenData = tokenRes.data as GoogleTokenData;

    if (!tokenData) return sendErrorRedirect(400, "could not fetch token");
    if (!tokenData.access_token)
      return sendErrorRedirect(400, "could not get access token");

    const userRes = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
        validateStatus: () => true,
      },
    );
    const user = userRes.data as GoogleUserData;

    if (!user)
      return sendErrorRedirect(404, "could not get user data from google");
    if (!user.id)
      return sendErrorRedirect(404, "could not get user id from google");
    if (!user.verified_email)
      return sendErrorRedirect(404, "please use a verified google account");

    const [savedAccount, savedUser, savedSession] = await this.saveData(
      user,
      tokenData,
    );

    await Auth.callbacks.handleCreate(savedAccount, savedUser, savedSession);

    const expirationDate = new Date(
      (savedAccount as AccountType).expiresAt || new Date(),
    );
    // Add an hour to expiration
    expirationDate.setHours(expirationDate.getHours() + 2);

    const cookie = request.cookies
    cookie.set("SessionToken", savedSession.sessionToken, {
      expires: expirationDate,
    });

    const referrer = new URL(
      cookie.get("redirectUrl")?.value || "/",
      process.env.NEXTAUTH_URL,
    );
    cookie.delete("redirectUrl");
    return Response.redirect(referrer, 302);
  }

  public async handleSignIn(request: IWebRequest, referer?: string) {
    const url = this.getOauthUrl();

    const cookies = request.cookies;
    cookies.set("redirectUrl", referer || "/");

    return sendJson({ url: url });
  }

  public async handleSignOut(request: IWebRequest) {
    return;
  }

  public async handleAuthCheck(request: IWebRequest, token: string) {
    const activeProvider = Auth.config[this.name];
    const session = await activeProvider.database.findSession({
      sessionToken: token,
    });

    if (!session) return false;

    let account = await activeProvider.database.findAccount({
      accountId: session.accountId,
    });
    if (!account || !account.expiresAt) return false;

    if (new Date() > new Date(account.expiresAt)) {
      // Token refresh logic
      const refreshedAccount = await this.refreshToken(account);
      if (!refreshedAccount) return false;
      account = refreshedAccount;
    }

    const user = await activeProvider.database.findUser({
      accountId: account.accountId,
    });

    const jwtResult = await decodeToken(token);
    if (!user || !jwtResult || jwtResult.payload.email !== user.email)
      return false;

    return { user: user } as Session;
  }

  private getRedirectUri(url?: string) {
    return `${url || process.env.NEXTAUTH_URL}/api/auth/callback/${this.name}`;
  }

  private getOauthUrl(): string {
    const base =
      this.credential.api_url || "https://accounts.google.com/o/oauth2/v2/auth";
    const url = new URL(base);
    url.searchParams.append("client_id", this.credential.client_id);
    url.searchParams.append("redirect_uri", this.getRedirectUri());
    url.searchParams.append("response_type", "code");
    url.searchParams.append("scope", this.credential.scopes.join(" "));
    url.searchParams.append("access_type", "offline");
    url.searchParams.append("prompt", "consent");
    return url.toString();
  }

  private async saveData(user: GoogleUserData, tokenData: GoogleTokenData) {
    const oauth = Auth.config[this.name];
    const accountSchema: AccountType = {
      accountId: user.id,
      provider: this.name,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: new Date(Date.now() + tokenData.expires_in * 1000),
      tokenType: tokenData.token_type,
      scope: tokenData.scope || "",
    };

    const userSchema: UserType = {
      accountId: user.id,
      email: user.email,
      name: user.email,
      image: user.picture,
      emailVerified: user.verified_email,
      provider: this.name,
    };

    const sessionToken = await createToken(
      {
        sub: user.email,
        provider: this.name,
        email: user.email,
        accountId: user.id,
      },
      accountSchema.expiresAt!,
    );

    const sessionSchema: SessionType = {
      sessionToken: sessionToken,
      expiresAt: accountSchema.expiresAt!,
      accountId: user.id,
      provider: this.name,
    };

    const createPromises: any = [
      oauth.database.createAccount(accountSchema),
      oauth.database.createUser(userSchema),
      oauth.database.createSession(sessionSchema),
    ];

    if (oauth.cache) {
      createPromises.push(
        oauth.cache.setValue(
          sessionSchema.sessionToken,
          JSON.stringify(accountSchema),
          {
            expire: Math.floor(
              (new Date(accountSchema.expiresAt!).getTime() - Date.now()) /
              1000,
            ),
          },
        ),
      );
    }

    return Promise.all(createPromises);
  }

  private async refreshToken(account: AccountType) {
    const data = new URLSearchParams();
    data.append("grant_type", "refresh_token");
    data.append("client_id", this.credential.client_id);
    data.append("client_secret", this.credential.client_secret);
    data.append("refresh_token", account.refreshToken);

    const refreshRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      data,
      {
        validateStatus: () => true,
      },
    );
    const refreshedTokenData = refreshRes.data as GoogleTokenData;

    console.log(refreshedTokenData);

    if (!refreshedTokenData.access_token) return null;

    const updatedAccount: AccountType = {
      ...account,
      refreshToken: refreshedTokenData.refresh_token,
      accessToken: refreshedTokenData.access_token,
      expiresAt: new Date(Date.now() + refreshedTokenData.expires_in * 1000),
    };

    await Auth.config[this.name].database.createAccount(updatedAccount);

    return updatedAccount;
  }
}
