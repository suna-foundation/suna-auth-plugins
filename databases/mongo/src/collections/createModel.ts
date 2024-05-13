// lib/createModel.ts
import mongoose, { type Model, model, type Schema } from "mongoose";

// Enhanced Generic Function for creating Mongoose models with support for HMR in development
export default function createModel<T, TModel extends Model<T> = Model<T>>(
  modelName: string,
  schema: Schema<T>,
  collectionName?: string
): TModel {
  // Use a single path for both development and production.
  // In development, check for the model in global scope to support HMR.
  if (mongoose.models[modelName]) {
    return mongoose.models[modelName] as TModel;
  }

  // Create a new model or retrieve from global scope in development.
  const modelInstance: TModel = model<T, TModel>(modelName, schema, collectionName);

  /*
  // Store the created model in global scope in development mode for HMR support.
  if (process.env.NODE_ENV === "development") {
      mongoose.models[modelName] = modelInstance;
  }
  */

  return modelInstance;
}
