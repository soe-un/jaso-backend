import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { config } from "../config";

export interface AuthRequest extends Request {
  user?: { id: string };
}

export const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ message: "토큰이 필요합니다." });
    return;
  }

  const token = authHeader.replace(/^Bearer\s+/i, "").trim();

  try {
    const decoded = jwt.verify(token, config.jwt.secret) as { sub: string };
    req.user = { id: decoded.sub }; // 요청 객체에 사용자 정보 추가
    next();
  } catch (error) {
    res.status(403).json({ message: "유효하지 않은 토큰입니다." });
    return;
  }
};
