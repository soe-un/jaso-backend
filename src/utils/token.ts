import jwt, { SignOptions } from "jsonwebtoken";
import { randomBytes } from "crypto";
import { config } from "../config";

export const generateAccessToken = (userId: string) => {
  const payload = { userId };
  const secret = config.jwt.secret;
  const options: SignOptions = {
    expiresIn: config.jwt.expiresIn,
  };

  return jwt.sign(payload, secret, options);
};

export const generateRefreshToken = () => {
  return randomBytes(64).toString("hex");
};
