import "server-only";
import nodemailer, { Transporter } from "nodemailer";
import { nanoid } from "nanoid";

import bcrypt from "bcrypt";
import {
  Auth,
  sendErrorRedirect,
  decodeToken,
  sendError,
  sendJson,
  createToken,
} from "suna-auth";
import {
  AccountType,
  IWebRequest,
  Session,
  SessionType,
  UserType,
} from "suna-auth/dist/types";

interface Config {
  tokenLifetime: number;
  host: string;
  from: string;
  port?: number;
  username?: string;
  password?: string;
  secure: boolean;
}

interface SmtpProviderToken {
  provider: "smtp";
  email: string;
  password: string;
  sub: string;
}

export class SmtpProvider {
  private static instance: SmtpProvider | null = null;
  name: "smtp" = "smtp";
  public credential: Config;
  private transporter: Transporter;

  private constructor(credential: Config) {
    // Initialize credential during the construction
    this.credential = credential;

    this.transporter = nodemailer.createTransport({
      host: credential.host,
      port: credential.port,
      //secure: credential.secure, // upgrade later with STARTTLS
      auth: {
        user: credential.username,
        pass: credential.password,
      },
    });
  }

  public static getInstance(config: Config): SmtpProvider {
    if (!this.instance) {
      this.instance = new SmtpProvider(config);
    }
    return this.instance;
  }

  /**
   * Handles the callback from an external authentication provider.
   * Obtains the authentication code from the request and retrieves the access token.
   * Retrieves user data using the access token and performs various checks.
   * Saves the user data and token information.
   * Sets the session token and redirects the user back to the referring page.
   *
   * @param {IWebRequest} request - The request object containing the authentication callback information.
   * @return {Response} - The redirect response.
   */
  public async handleCallback(request: IWebRequest) {
    /*
     * This is going to be the callback for when the link is clicked from the mail inbox of the person its sent from
     * */

    const searchQuery = request.query;
    const code = searchQuery.get("code");

    if (!code)
      return sendErrorRedirect(400, "no code provided, please try again");

    const sessionTokenString = await Auth.config[this.name].cache.getValue(
      code
    );
    if (!sessionTokenString)
      return sendErrorRedirect(
        404,
        "your sign in code has expired, please try again"
      );

    const sessionToken = await decodeToken<SmtpProviderToken>(
      sessionTokenString
    );
    if (!sessionToken)
      return sendErrorRedirect(
        404,
        "your sign in code has expired, please try again"
      );

    const payload = sessionToken.payload;
    const [savedAccount, savedUser, savedSession, cacheValue] =
      await this.saveData(request, payload);

    await Auth.callbacks.handleCreate(savedAccount, savedUser, savedSession);

    const cookie = request.cookies;
    const referrer = new URL(
      cookie.get("redirectUrl")?.value || "/",
      process.env.NEXTAUTH_URL
    );
    cookie.delete("redirectUrl");

    return Response.redirect(referrer, 302);
  }

  /**
   * Handles the sign-in process and returns the OAuth URL.
   *
   * @param {IWebRequest} request - The request object.
   * @param {string} [referer] - The referer URL.
   * @returns {Promise<Object>} - The JSON response containing the OAuth URL.
   */
  public async handleSignIn(request: IWebRequest, referer?: string) {
    const activeProvider = Auth.config[this.name];
    const email = request.headers.get("email");
    const password = request.headers.get("password");
    const method = request.headers.get("method");

    if (!email || !password)
      return sendError(400, "Please provide a email and password");

    const [account, user] = await Promise.all([
      activeProvider.database.findAccount({
        accountId: email,
        provider: this.name,
      }),
      activeProvider.database.findUser({
        accountId: email,
        provider: this.name,
      }),
    ]);

    if (account && user && method !== "updatePassword") {
      const isPasswordCorrect = await validateHash(
        password,
        account.accessToken
      );
      if (!isPasswordCorrect) return sendError(401, "wrong password");

      const [sessionSchema] = await this.createSession(request, account, user);
      if (sessionSchema)
        return sendJson({ url: referer }) || sendJson("successfully sign in");
      else return sendError(500, "could not sign in, please try again");
    }

    if (!method) return sendError(400, "no account with this email");
    if (method === "updatePassword") {
      const code = await this.createUpdateCode({ email, password });
      await this.transporter.sendMail({
        from: `<${this.credential.from}>`,
        to: email,
        subject: "Update Password",
        text: `You can ignore this email if you did not request a password change
          
          ${process.env.NEXTAUTH_URL}/api/auth/callback/smtp?code=${code}`,
      });

      const redirectUpdatePassword = new URL(
        `/api/auth/message?message=Please check your inbox to change your password`,
        process.env.NEXTAUTH_URL
      );
      return sendJson({ url: redirectUpdatePassword });
    }

    if (method == "createAccount") {
      const code = await this.createUpdateCode({ email, password });
      await this.transporter.sendMail({
        from: `<${this.credential.from}>`,
        to: email,
        subject: "Verification Email",
        text: `${process.env.NEXTAUTH_URL}/api/auth/callback/smtp?code=${code}`,
      });

      //cookies().set({name: "redirectUrl", value: referer || "/"});
      const redirectCreateAccount = new URL(
        `/api/auth/message?message=Please check your inbox for a verification email`,
        process.env.NEXTAUTH_URL
      );
      return sendJson({ url: redirectCreateAccount });
    }

    return sendError(500, "nothing exists");
  }

  public async handleSignOut(request: IWebRequest) {
    return;
  }

  public async handleAuthCheck(token: string) {
    const selectedProvider = Auth.config[this.name];
    const session = await selectedProvider.database.findSession({
      sessionToken: token,
    });
    if (!session) return false;

    const account = await selectedProvider.database.findAccount({
      accountId: session.accountId,
      provider: this.name,
    });
    if (!account) return false;

    const user = await selectedProvider.database.findUser({
      accountId: account.accountId,
    });
    const jwtResult = await decodeToken(token);

    if (
      !user ||
      !jwtResult ||
      jwtResult.payload.email !== user.email ||
      !jwtResult.payload.exp ||
      new Date() > new Date(jwtResult.payload.exp * 1000)
    )
      return false;

    return { user: user } as Session;
  }

  private async purgeSessions(user: UserType) {
    const smtpProvider = Auth.config[this.name];
    await smtpProvider.database.purgeSessions(user);
  }

  private async createSession(request: IWebRequest, accountSchema: AccountType, user: UserType) {
    const smtpProvider = Auth.config[this.name];
    const expirationDate = new Date(Date.now() + this.credential.tokenLifetime);
    const sessionToken: string = await createToken(
      {
        provider: "smtp",
        sub: user.email,
        email: user.email,
        accountId: user.email,
      },
      expirationDate
    );

    const sessionSchema: SessionType = {
      sessionToken: sessionToken,
      accountId: user.email,
      expiresAt: new Date(Date.now() + this.credential.tokenLifetime),
      provider: "smtp",
    };

    const createPromises: any = [
      smtpProvider.database.createSession(sessionSchema),
    ];

    if (smtpProvider.cache) {
      createPromises.push(
        smtpProvider.cache.setValue(
          sessionSchema.sessionToken,
          JSON.stringify(accountSchema),
          {
            expire: Math.floor(
              (new Date(expirationDate).getTime() - Date.now()) / 1000
            ),
          }
        )
      );
    }

    const cookie = request.cookies;
    cookie.set("SessionToken", sessionSchema.sessionToken, {
      expires: accountSchema.expiresAt,
    });

    return Promise.all(createPromises);
  }

  private async createUpdateCode({
    email,
    password,
  }: {
    email: string;
    password: string;
  }) {
    const activeProvider = Auth.config[this.name];
    const code = nanoid();
    const passwordVerificationToken = await createToken(
      {
        provider: "smtp",
        email: email,
        password: password,
        sub: email,
      },
      new Date(Date.now() + 900000)
    );
    // Save the value to the providers cache and expire in 15min
    await activeProvider.cache.setValue(code, passwordVerificationToken, {
      expire: 900000,
    });

    return code;
  }

  private async saveData(request: IWebRequest, payload: SmtpProviderToken) {
    const activeProvider = Auth.config[this.name];

    const userSchema: UserType = {
      accountId: payload.email,
      email: payload.email,
      name: payload.email.split("@")[0],
      image: `/icons/unknown-user.png`,
      emailVerified: true,
      provider: this.name,
    };

    const accessToken = await createHash(payload.password);
    const accountSchema: AccountType = {
      accountId: payload.email,
      provider: "smtp",
      accessToken: accessToken,
      refreshToken: "",
      expiresAt: undefined,
      scope: "email password",
    };

    // We run purge sessions so that no sessions will exist when the password is changed
    await this.purgeSessions(userSchema);

    const createPromises: any = [
      activeProvider.database.createAccount(accountSchema),
      activeProvider.database.createUser(userSchema),
      ...(await this.createSession(request, accountSchema, userSchema)),
    ];

    return Promise.all(createPromises);
  }
}

/**
 * Creates a hash of the provided data using bcrypt.
 *
 * @param {string} data - The data to hash.
 * @returns {Promise<string>} - A promise that resolves to the hash.
 * @throws {Error} - If an error occurred during the hashing process.
 */
export const createHash = async (data: string): Promise<string> => {
  try {
    const salt = await bcrypt.genSalt(10); // replace 10 with your desired number of salt rounds
    const hash = await bcrypt.hash(data, salt);

    return hash;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

/**
 * Validates whether the given data matches the provided hash.
 *
 * @param {string} data - The data to be validated.
 * @param {string} hash - The hash to be compared against.
 * @returns {Promise<boolean>} - A promise that resolves to a boolean value indicating whether the data matches the hash.
 */
export const validateHash = async (
  data: string,
  hash: string
): Promise<boolean> => {
  return bcrypt.compare(data, hash);
};
