import "server-only";
import { NextRequest } from "next/server";
import { cookies } from "next/headers";
import axios from "axios";

import {
  Provider,
  Session,
  SessionType,
  UserType,
  AccountType,
} from "suna-auth/dist/types";
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
  authorization: string;
}

export class DiscordProvider implements Provider {
  private static instance: DiscordProvider | null = null;
  name: "discord" = "discord";
  public credential: Config;

  private constructor(credential: Config) {
    this.credential = credential;
  }

  public static getInstance(config: Config): DiscordProvider {
    if (!this.instance) {
      this.instance = new DiscordProvider(config);
    }
    return this.instance;
  }

  public async handleCallback(request: NextRequest) {
    const searchParams = request.nextUrl.searchParams;
    const code = searchParams.get("code");
    const error = searchParams.get("error");
    const error_description = searchParams.get("error_description");

    const cookie = cookies();
    const referrer = new URL(
      cookie.get("redirectUrl")?.value || "/",
      process.env.NEXTAUTH_URL
    );
    cookie.delete("redirectUrl");

    if (error || error_description) {
      if (
        error_description ==
        "The resource owner or authorization server denied the request"
      )
        return Response.redirect(referrer, 302);
      return sendErrorRedirect(
        401,
        error_description || "The discord oauth failed, and did not error"
      );
    }
    if (!code) return sendErrorRedirect(400, "no ?code provided");

    const token = await this.getToken(code);
    const tokenData = token.data;

    if (!tokenData || !tokenData.token_type || !tokenData.access_token)
      return sendErrorRedirect(404, "discord token data request failed");

    const userRes = await this.getUser(tokenData);
    const user = userRes.data;

    if (!user)
      return sendErrorRedirect(404, "could not get user data from discord");

    if (!user.id)
      return sendErrorRedirect(404, "could not get user id from discord");

    if (!user.verified)
      return sendErrorRedirect(404, "please use a verified discord account");

    const [savedAccount, savedUser, savedSession] = await this.saveData(
      user,
      tokenData
    );

    await Auth.callbacks.handleCreate(savedAccount, savedUser, savedSession);

    cookie.set({
      name: "SessionToken",
      value: savedSession.sessionToken,
      expires: (savedAccount as AccountType).expiresAt,
    });

    return Response.redirect(referrer, 302);
  }

  public async handleSignIn(request: NextRequest, referer?: string) {
    const url = this.getOauthUrl(request);

    cookies().set({ name: "redirectUrl", value: referer || "/" });
    cookies().set({
      name: "signInHeaders",
      value: JSON.stringify({
        scopes: request.headers.get("scopes") || undefined,
        authorization: request.headers.get("authorization") || undefined,
        client_id: request.headers.get("client_id") || undefined,
        client_secret: request.headers.get("client_secret") || undefined,
      }),
    });

    return sendJson({ url: url });
  }

  public async handleSignOut(request: NextRequest) {
    return;
  }

  public async handleAuthCheck(token: string) {
    const discordProvider = Auth.config[this.name];
    const session = await discordProvider.database.findSession({
      sessionToken: token,
    });
    if (!session) return false;

    const account = await discordProvider.database.findAccount({
      accountId: session.accountId,
    });
    if (!account || !account.expiresAt) return false;

    if (new Date() > new Date(account.expiresAt)) {
      // Need to implement token refresh, for now just error it out
      /*
        const refreshed = await refreshSession({
          provider: "discord",
          cookieId: SessionToken.value,
          account: account,
        });
        if (!refreshed) return false;
      */
      return false;
    }

    const user = await discordProvider.database.findUser({
      accountId: account.accountId,
    });

    const jwtResult = await decodeToken(token);
    if (!user || !jwtResult || jwtResult.payload.email !== user.email)
      return false;

    return { user: user } as Session;
  }

  private getRedirectUri(url?: string) {
    return `${url || process.env.NEXTAUTH_URL}/api/auth/callback/discord`;
  }

  private getOauthUrl(request: NextRequest): string {
    const scopes = request.headers.get("scopes") || undefined;
    const authorization = request.headers.get("authorization") || undefined;
    const client_id = request.headers.get("client_id") || undefined;

    return `${
      authorization || this.credential.authorization
    }?scope=${scopes || this.credential.scopes.join("+")}&client_id=${
      client_id || this.credential.client_id
    }&response_type=code&redirect_uri=${this.getRedirectUri()}`;
  }

  private async getToken(code: string) {
    const data = new URLSearchParams();
    data.append("grant_type", "authorization_code");
    data.append("code", code);
    data.append("redirect_uri", this.getRedirectUri());

    return axios({
      method: "post",
      url: "https://discord.com/api/oauth2/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      auth: {
        username: this.credential.client_id,
        password: this.credential.client_secret,
      },
      data: data.toString(),
      validateStatus: () => true,
    });
  }

  private async getUser(tokenData: any) {
    return await axios.get("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `${tokenData.token_type} ${tokenData.access_token}`,
      },
    });
  }

  private async saveData(user: any, tokenData: any) {
    const oauth = Auth.config[this.name];
    const accountSchema = {
      accountId: user.id,
      provider: "discord",
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: new Date(Date.now() + tokenData.expires_in * 1000),
      tokenType: tokenData.token_type,
      scope: tokenData.scope || "",
    };

    const userSchema: UserType = {
      accountId: user.id,
      email: user.email,
      name: user.username,
      image: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
      emailVerified: user.verified,
      provider: this.name,
    };

    const sessionToken = await createToken(
      {
        sub: user.email,
        provider: "discord",
        email: user.email,
        accountId: user.id,
      },
      accountSchema.expiresAt
    );

    const sessionSchema: SessionType = {
      sessionToken: sessionToken,
      expiresAt: accountSchema.expiresAt,
      accountId: user.id,
      provider: "discord",
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
              (new Date(accountSchema.expiresAt).getTime() - Date.now()) / 1000
            ),
          }
        )
      );
    }

    return Promise.all(createPromises);
  }
}
