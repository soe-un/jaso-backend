import express, { Request, Response } from "express";
import prisma from "../prisma";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

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

    // 사용자 생성
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name,
      },
      select: {
        id: true,
        email: true,
        name: true,
        profileImage: true,
        createdAt: true,
      },
    });

    res.status(201).json({ message: "회원가입 성공!", user: newUser });
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

    // 1. 사용자가 DB에 존재하는지 확인
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 잘못되었습니다." });
      return;
    }

    // 2. 비밀번호 비교
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 잘못되었습니다." });
      return;
    }

    // 3️. JWT 토큰 생성
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    // 4️. 로그인 성공 응답
    res.status(200).json({ message: "로그인 성공!", token, user });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({ message: "서버 오류 발생" });
  }
});

export default router;
