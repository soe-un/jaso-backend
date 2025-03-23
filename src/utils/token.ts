import jwt, { SignOptions } from "jsonwebtoken";
import { config } from "../config";

export const generateAccessToken = (userId: string) => {
  const payload = { sub: userId };
  const secret = config.jwt.secret;
  const options: SignOptions = {
    expiresIn: config.jwt.expiresIn,
  };

  return jwt.sign(payload, secret, options);
};

export const generateRefreshToken = (userId: string) => {
  const payload = { sub: userId };
  const secret = config.jwt.refreshSecret;
  const options: SignOptions = {
    expiresIn: config.jwt.refreshExpiresIn,
  };

  return jwt.sign(payload, secret, options);
};
