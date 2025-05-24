import "@nobush/server-only";

import {
  AccountType,
  IWebRequest,
  Provider,
  Session,
  SessionType,
  UserType,
} from "suna-auth/dist/types";
import {
  Auth,
  createToken,
  decodeToken,
  sendErrorRedirect,
  sendJson,
} from "suna-auth";

interface Config {
  bot_id: string;
  scope: string;
  public_key: string;
  nonce: string;
}

export class TelegramProvider implements Provider {
  private static instance: TelegramProvider | null = null;
  name: "telegram" = "telegram";
  public credential: Config;

  private constructor(credential: Config) {
    this.credential = credential;
  }

  public static getInstance(config: Config): TelegramProvider {
    if (!this.instance) {
      this.instance = new TelegramProvider(config);
    }
    return this.instance;
  }

  public async handleCallback(request: IWebRequest): Promise<Response> {
    const tgAuthResult = request.query.get("tgAuthResult");

    let redirectCount = parseInt(request.query.get("redirectCount") || "0");

    if (!tgAuthResult) {
      redirectCount += 1;

      if (redirectCount > 2) {
        return sendErrorRedirect(
          400,
          "Could not get tgAuthResult, please try to login again"
        );
      } else {
        return new Response(
          `<!DOCTYPE html>
<html lang="en">
<head>
  <script>
    window.onload = function() {
      const hash = window.location.hash;
      if (hash) {
        const hashValue = hash.replace('#tgAuthResult=', '');
        const params = new URLSearchParams(window.location.search);

        params.append('tgAuthResult', hashValue);

        const newUrl = window.location.origin + window.location.pathname + '?' + params.toString();
        window.location.replace(newUrl);
      }
    };
  </script>
</head>
<body>
  <h1>Redirecting...</h1>
</body>
</html>`,
          {
            status: 200,
            headers: {
              "Content-Type": "text/html",
            },
          }
        );
      }
    }

    // Initialize cookies and referrer
    const cookie = request.cookies;
    const referrer = new URL(
      cookie.get("redirectUrl")?.value || "/",
      process.env.NEXTAUTH_URL
    );
    cookie.delete("redirectUrl");

    // Decode base64 tgAuthResult
    const tgAuthResultBuffer = Buffer.from(tgAuthResult, "base64");
    const tgAuthResultString = tgAuthResultBuffer.toString("utf8");

    if (!tgAuthResultString)
      return sendErrorRedirect(400, "No tgAuthResult provided");

    const tgAuthResultJson = JSON.parse(tgAuthResultString);
    if (!tgAuthResultJson.id)
      return sendErrorRedirect(404, "Could not get user data from Telegram");

    const [savedAccount, savedUser, savedSession] = await this.saveData(
      tgAuthResultJson
    );

    await Auth.callbacks.handleCreate(savedAccount, savedUser, savedSession);

    cookie.set("SessionToken", savedSession.sessionToken, {
      expires: (savedAccount as AccountType).expiresAt,
    });

    return Response.redirect(referrer, 302);
  }

  public async handleSignIn(request: IWebRequest, referer?: string) {
    const url = this.getOauthUrl();

    request.cookies.set("redirectUrl", referer || "/");

    return sendJson({ url: url });
  }

  public async handleSignOut(request: IWebRequest) {
    return;
  }

  public async handleAuthCheck(request: IWebRequest, token: string) {
    const telegramProvider = Auth.config[this.name];
    const session = await telegramProvider.database.findSession({
      sessionToken: token,
    });
    if (!session) return false;

    const account = await telegramProvider.database.findAccount({
      accountId: session.accountId,
    });
    if (!account || !account.expiresAt) return false;

    if (new Date() > new Date(account.expiresAt)) {
      return false;
    }

    const user = await telegramProvider.database.findUser({
      accountId: account.accountId,
    });

    const jwtResult = await decodeToken(token);
    if (!user || !jwtResult || jwtResult.payload.email !== user.email)
      return false;

    return { user: user } as Session;
  }

  private getRedirectUri(url?: string) {
    return `${url || process.env.NEXTAUTH_URL}/api/auth/callback/telegram`;
  }

  private getOauthUrl(redirect_uri?: string): string {
    const url = new URL("https://oauth.telegram.org/auth");
    url.searchParams.set("domain", "telegrampassport");
    url.searchParams.set("scope", this.credential.scope);
    url.searchParams.set("nonce", this.credential.nonce);
    url.searchParams.set("bot_id", this.credential.bot_id);
    url.searchParams.set("public_key", this.credential.public_key);
    url.searchParams.set("origin", this.getRedirectUri());
    url.searchParams.set("callback_url", this.getRedirectUri());

    return url.toString();
  }

  private async saveData(user: {
    id: number;
    first_name: string;
    photo_url: string;
    auth_date: number;
    hash: string;
  }) {
    const oauth = Auth.config[this.name];
    const accountSchema = {
      accountId: `${user.id}`,
      provider: "telegram",
      accessToken: "",
      refreshToken: "",
      expiresAt: new Date(Date.now() + 3600 * 24000), // 1 hour
      tokenType: "",
      scope: this.credential.scope || "",
    } satisfies AccountType;

    const userSchema = {
      accountId: `${user.id}`,
      email: "",
      name: user.first_name,
      image: user.photo_url,
      emailVerified: true,
      provider: this.name,
    } satisfies UserType;

    const sessionToken = await createToken(
      {
        sub: user.first_name,
        provider: "telegram",
        email: "",
        accountId: `${user.id}`,
      },
      accountSchema.expiresAt
    );

    const sessionSchema = {
      sessionToken: sessionToken,
      expiresAt: accountSchema.expiresAt,
      accountId: `${user.id}`,
      provider: "telegram",
    } satisfies SessionType;

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
