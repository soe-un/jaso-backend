import express, { Request, Response } from "express";
import prisma from "../prisma";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {
  sendResetPasswordEmail,
  sendVerificationEmail,
} from "../utils/emailService";
import { randomBytes } from "crypto";

const router = express.Router();
const SECRET_KEY = process.env.JWT_SECRET || "supersecret";

// 회원가입 API
router.post("/register", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, name } = req.body;

    // 필수 필드 검증
    if (!email || !password || !name) {
      res.status(400).json({ message: "필수 입력 요소가 없습니다." });
      return;
    }

    // 이메일 중복 확인
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ message: "이미 가입된 이메일입니다." });
      return;
    }

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);

    // 이메일 인증 토큰 생성
    const verificationToken = randomBytes(32).toString("hex");

    // 사용자 생성
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name,
        isVerified: false,
        emailVerifyToken: verificationToken,
      },
      select: {
        id: true,
        email: true,
        name: true,
        isVerified: true,
        createdAt: true,
      },
    });

    await sendVerificationEmail(email, verificationToken);

    res
      .status(201)
      .json({ message: "회원가입 성공! 이메일을 확인하세요.", user: newUser });
    return;
  } catch (error) {
    console.error("회원가입 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

// 로그인 API
router.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // 사용자가 DB에 존재하는지 확인
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 잘못되었습니다." });
      return;
    }

    // 비밀번호 비교
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 잘못되었습니다." });
      return;
    }

    // 이메일 인증 확인
    if (!user.isVerified) {
      res.status(403).json({ message: "이메일 인증이 완료되지 않았습니다." });
      return;
    }

    // JWT 토큰 생성
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    // 로그인 성공 응답
    res.status(200).json({ message: "로그인 성공!", token, user });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

// 이메일 인증 확인 API
router.get("/verify-email/:token", async (req: Request, res: Response) => {
  const { token } = req.params;

  try {
    const user = await prisma.user.findFirst({
      where: { emailVerifyToken: token },
    });

    if (!user) {
      res.status(400).json({ message: "유효하지 않은 인증 링크입니다." });
      return;
    }

    // 이메일 인증 완료 처리
    await prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        emailVerifyToken: null,
      },
    });

    res
      .status(200)
      .json({ message: "이메일 인증이 완료되었습니다. 로그인하세요!" });
  } catch (error) {
    console.error("이메일 인증 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

// 비밀번호 재설정 요청 API
router.post("/forgot-password", async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !user.isVerified) {
      res
        .status(404)
        .json({ message: "가입된 이메일이 없거나 인증되지 않았습니다." });
      return;
    }

    const token = randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 60); // 1시간 후 만료

    await prisma.user.update({
      where: { email },
      data: {
        resetPasswordToken: token,
        resetPasswordExpires: expires,
      },
    });

    await sendResetPasswordEmail(email, token);

    res
      .status(200)
      .json({ message: "비밀번호 재설정 링크를 이메일로 전송했습니다." });
  } catch (error) {
    console.error("비밀번호 재설정 요청 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

// 비밀번호 재설정 API
router.post("/reset-password/:token", async (req: Request, res: Response) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    res.status(400).json({ message: "새 비밀번호를 6자 이상 입력하세요." });
    return;
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        resetPasswordToken: token,
        resetPasswordExpires: {
          gte: new Date(), // 만료되지 않은 경우만
        },
      },
    });

    if (!user) {
      res.status(400).json({ message: "유효하지 않거나 만료된 토큰입니다." });
      return;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
      },
    });

    res.status(200).json({ message: "비밀번호가 성공적으로 변경되었습니다." });
  } catch (error) {
    console.error("비밀번호 재설정 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

export default router;
