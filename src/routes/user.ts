import express, { Request, Response } from "express";
import prisma from "../prisma";
import { authenticateToken, AuthRequest } from "../middleware/authMiddleware";

const router = express.Router();

// 보호된 API: 사용자 프로필 조회
router.get(
  "/profile",
  authenticateToken,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({ message: "사용자 정보가 없습니다." });
        return;
      }

      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, createdAt: true }, // 비밀번호 제외
      });

      if (!user) {
        res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        return;
      }

      res.status(200).json({ message: "프로필 조회 성공!", user });
      return;
    } catch (error) {
      console.error("프로필 조회 오류:", error);
      res.status(500).json({ message: "서버 오류 발생" });
      return;
    }
  }
);

export default router;
