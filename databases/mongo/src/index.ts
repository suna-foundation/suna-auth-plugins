import 'server-only'
import mongoose, {Document} from "mongoose";
import {AccountType, Database, SessionType, UserType} from "suna-auth/src/types";
import Accounts from "./collections/accounts";
import Users from "./collections/users";
import Sessions from "./collections/sessions";

interface Config {
  mongodb_url: string;
}


export class MongooseAuth implements Database {
  private static instance: MongooseAuth | null = null;
  private instance: MongooseAuth | null = null;

  private constructor(config: Config) {
    mongoose.connect(config.mongodb_url).then(() => console.log('Connected to Mongoose')).catch(() => console.log('Could not connect to mongoose'))
  }

  public static getInstance(config: Config): MongooseAuth {
    if (!this.instance) {
      this.instance = new MongooseAuth(config);
    }
    return this.instance
  }

  public async createAccount(data: AccountType): Promise<AccountType> {
    const account = await Accounts.findOneAndUpdate(
      {accountId: data.accountId},
      data,
      {new: true, upsert: true},
    );
    return account.toJSON();
  }

  public async createUser(data: UserType): Promise<UserType> {
    const user = await Users.findOneAndUpdate(
      {accountId: data.accountId},
      data,
      {new: true, upsert: true},
    );
    return user.toJSON();
  }

  public async createSession(data: SessionType): Promise<SessionType> {
    const session = new Sessions(data);
    await session.save()

    return session.toJSON();
  }


  public async findAccount(data: Partial<AccountType>): Promise<AccountType | undefined> {
    try {
      const account = await Accounts.findOne(data);
      return account?.toJSON();
    } catch (e) {
      console.error(e);
      return undefined;
    }
  }

  public async findUser(data: Partial<UserType>): Promise<UserType | undefined> {
    try {
      const user = await Users.findOne(data);
      return user?.toJSON();
    } catch (e) {
      console.error(e);
      return undefined;
    }
  }

  public async findSession(data: Partial<SessionType>): Promise<SessionType | undefined> {
    try {
      const session = await Sessions.findOne(data);
      return session?.toJSON();
    } catch (e) {
      console.error(e);
      return undefined;
    }
  }

  public async purgeSessions(user: UserType) {
    try {
      await Sessions.deleteMany({
        accountId: user.accountId
      })
      return true
    } catch (e) {
      return false
    }
  }
}