import express, { Request, Response } from "express";
import prisma from "../prisma";
import bcrypt from "bcrypt";
import axios from "axios";
import {
  sendResetPasswordEmail,
  sendVerificationEmail,
} from "../utils/emailService";
import { randomBytes } from "crypto";
import { generateAccessToken, generateRefreshToken } from "../utils/token";
import { config } from "../config";

const router = express.Router();

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
  const { email, password } = req.body;

  // 사용자가 DB에 존재하는지 확인
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    res.status(401).json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    return;
  }
  // 이메일 인증 확인
  if (!user.isVerified) {
    res.status(403).json({ message: "이메일 인증이 필요합니다." });
    return;
  }

  const accessToken = generateAccessToken(user.id);
  const refreshToken = generateRefreshToken();
  const expiresAt = new Date(Date.now() + config.refreshToken.expiresInMs);

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt,
    },
  });

  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: config.mode.dev ? false : true, // true: HTTPS에서만 동작
      sameSite: "strict",
      maxAge: config.refreshToken.expiresInMs,
    })
    .json({
      message: "로그인 성공!",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        profileImage: user.profileImage,
      },
    });
});

// 토큰 refresh API
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    res.status(401).json({ message: "Refresh Token이 없습니다." });
    return;
  }

  const savedToken = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
    include: { user: true },
  });

  if (!savedToken || savedToken.expiresAt < new Date()) {
    res.status(403).json({ message: "Refresh Token이 유효하지 않습니다." });
    return;
  }

  const newAccessToken = generateAccessToken(savedToken.user.id);
  res.status(200).json({ accessToken: newAccessToken });
});

// 로그아웃 API
router.post("/logout", async (req: Request, res: Response): Promise<void> => {
  const refreshToken = req.cookies?.refreshToken;

  if (refreshToken) {
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  }

  res.clearCookie("refreshToken").json({ message: "로그아웃 되었습니다." });
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

router.get("/kakao/callback", async (req: Request, res: Response) => {
  const code = req.query.code as string;

  try {
    // 1. 인가 코드로 카카오 토큰 요청
    const tokenRes = await axios.post(
      "https://kauth.kakao.com/oauth/token",
      null,
      {
        params: {
          grant_type: "authorization_code",
          client_id: process.env.KAKAO_CLIENT_ID,
          redirect_uri: process.env.KAKAO_REDIRECT_URI,
          code,
        },
        headers: {
          "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
        },
      }
    );

    const accessToken = tokenRes.data.access_token;

    // 2. 사용자 정보 조회
    const userRes = await axios.get("https://kapi.kakao.com/v2/user/me", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const kakaoUser = userRes.data;

    config.mode.dev ??
      console.log(
        "✅ 카카오 사용자 정보 응답:",
        JSON.stringify(kakaoUser, null, 2)
      );

    const kakaoId = String(kakaoUser.id); // 카카오 고유 ID
    const nickname = kakaoUser.properties?.nickname || "카카오유저";
    const kakaoEmail = kakaoUser.kakao_account?.email;
    const profileImage = kakaoUser.properties?.profile_image || null;

    let user = await prisma.user.findFirst({
      where: {
        // 이메일 없을 경우 ID 기반으로 처리
        socialId: kakaoId,
        provider: "kakao",
      },
    });

    if (!user) {
      user = await prisma.user.create({
        data: {
          email: kakaoEmail ?? `kakao_${kakaoId}@noemail.com`, // 가짜 이메일 생성
          name: nickname,
          profileImage,
          isVerified: true,
          password: "kakao_dummy_password",
          provider: "kakao",
          socialId: kakaoId,
        },
      });
    }

    // 5. Access + Refresh 발급
    const accessTokenJwt = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken();

    const expiresAt = new Date(Date.now() + config.refreshToken.expiresInMs);

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt,
      },
    });

    // 6. 쿠키로 Refresh Token 설정
    res
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: config.mode.dev ? false : true,
        sameSite: "strict",
        maxAge: config.refreshToken.expiresInMs,
      })
      .redirect(`${config.server.url}/auth/success?token=${accessTokenJwt}`);
  } catch (err) {
    console.error("카카오 로그인 실패", err);
    res.status(500).json({ message: "카카오 로그인 실패" });
  }
});

export default router;
