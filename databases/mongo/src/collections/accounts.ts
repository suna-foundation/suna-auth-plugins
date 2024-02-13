import { Schema, type Document, type Model } from 'mongoose';
import createModel from "./createModel";

export interface AccountType {
  accountId: string;
  provider: string;
  accessToken: string;
  refreshToken: string;
  expiresAt?: Date | undefined;
  tokenType?: string;
  scope: string;
}

interface AccountEntryType extends Document, AccountType {};

export const AccountEntrySchema = new Schema<AccountEntryType>({
  accountId: { type: String, required: true },
  provider: { type: String, required: true },
  accessToken: { type: String, required: true },
  refreshToken: { type: String, required: true },
  expiresAt: { type: Date, required: false },
  tokenType: { type: String, required: false },
  scope: { type: String, required: true },
});

export type AccountEntry = Model<AccountEntryType>
export default createModel<AccountEntryType, AccountEntry>("Accounts", AccountEntrySchema, "accounts");