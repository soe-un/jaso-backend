import { SignOptions } from "jsonwebtoken";

export const config = {
  jwt: {
    secret: process.env.JWT_SECRET || "textsecretevalye",
    refreshSecret: process.env.JWT_SECRET || "textsecretevalye",
    refreshExpiresIn: "7d" as SignOptions["expiresIn"],
    expiresIn: "15m" as SignOptions["expiresIn"],
  },
  refreshToken: {
    expiresInMs: 7 * 24 * 60 * 60 * 1000, // 7일
  },
  server: {
    port: process.env.PORT || 5000,
    env: process.env.NODE_ENV || "development",
    dev: true,
    url: process.env.SERVER_URL || "http://localhost:5000",
  },
  mode: {
    dev: true,
  },
  email: {
    user: process.env.EMAIL_USER || "",
    pass: process.env.EMAIL_PASS || "",
  },
};
