import { Schema, type Document, type Model } from 'mongoose';
import createModel from './createModel';

export interface UserType {
  name: string;
  email: string;
  image: string;
  accountId: string;
  provider: string;
  emailVerified: boolean;
}

interface UserEntryType extends Document, UserType {};

export const UserEntrySchema = new Schema<UserEntryType>({
  name: { type: String, required: true },
  email: { type: String, required: true },
  image: { type: String, required: true },
  accountId: { type: String, required: true },
  provider: { type: String, required: true },
  emailVerified: { type: Boolean, required: true },
});

export type UserEntry = Model<UserEntryType>
export default createModel<UserEntryType, UserEntry>("Users", UserEntrySchema, "users");