import express, { Request, Response } from "express";
import prisma from "../prisma";
import { authenticateToken, AuthRequest } from "../middleware/authMiddleware";
import bcrypt from "bcrypt";

const router = express.Router();

// 보호된 API: 프로필 조회
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
    }
  }
);

// 보호된 API: 비밀번호 변경
router.put(
  "/change-password",
  authenticateToken,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;
      const { currentPassword, newPassword } = req.body;

      if (!userId) {
        res.status(401).json({ message: "인증이 필요합니다." });
        return;
      }

      if (!currentPassword || !newPassword) {
        res
          .status(400)
          .json({ message: "현재 비밀번호와 새로운 비밀번호를 입력하세요." });
        return;
      }

      // 1️. 현재 사용자 찾기
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        return;
      }

      // 2️. 현재 비밀번호 검증
      const isPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password
      );
      if (!isPasswordValid) {
        res.status(400).json({ message: "현재 비밀번호가 올바르지 않습니다." });
        return;
      }

      // 3️. 새로운 비밀번호 해싱 후 저장
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({
        where: { id: userId },
        data: { password: hashedNewPassword },
      });

      res
        .status(200)
        .json({ message: "비밀번호가 성공적으로 변경되었습니다." });
    } catch (error) {
      console.error("비밀번호 변경 오류:", error);
      res.status(500).json({ message: "서버 오류 발생" });
    }
  }
);

// 보호된 API: 회원 탈퇴
router.delete(
  "/delete-account",
  authenticateToken,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({ message: "인증이 필요합니다." });
        return;
      }

      // 1️⃣ 현재 사용자 확인
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
        return;
      }

      // 2️⃣ 사용자 삭제 (관련 데이터도 삭제 필요!)
      await prisma.user.delete({ where: { id: userId } });

      res.status(200).json({ message: "회원 탈퇴가 완료되었습니다." });
    } catch (error) {
      console.error("회원 탈퇴 오류:", error);
      res.status(500).json({ message: "서버 오류 발생" });
    }
  }
);

// 보호된 API: 프로필 수정
router.put(
  "/update-profile",
  authenticateToken,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const userId = req.user?.id;
      const { name, profileImage } = req.body;

      if (!userId) {
        res.status(401).json({ message: "인증이 필요합니다." });
        return;
      }

      if (!name && !profileImage) {
        res.status(400).json({ message: "수정할 정보를 입력하세요." });
        return;
      }

      // 1️. 변경할 데이터 생성
      const updateData: Record<string, string> = {};
      if (name) updateData.name = name;
      if (profileImage) updateData.profileImage = profileImage;

      // 2️. 사용자 정보 업데이트
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
          id: true,
          email: true,
          name: true,
          profileImage: true,
          createdAt: true,
        },
      });

      res.status(200).json({
        message: "프로필이 성공적으로 수정되었습니다.",
        user: updatedUser,
      });
    } catch (error) {
      console.error("프로필 수정 오류:", error);
      res.status(500).json({ message: "서버 오류 발생" });
    }
  }
);

export default router;
