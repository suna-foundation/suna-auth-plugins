import { randomBytes, pbkdf2Sync, timingSafeEqual } from "crypto";

export const createHash = async (data: string): Promise<string> => {
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(data, salt, 100000, 64, "sha512").toString("hex");
  return `${salt}:${hash}`;
};

export const validateHash = async (
  data: string,
  stored: string
): Promise<boolean> => {
  const [salt, originalHash] = stored.split(":");
  const hash = pbkdf2Sync(data, salt, 100000, 64, "sha512").toString("hex");
  return timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(originalHash, "hex"));
};