import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// 라우트 추가
app.use("/auth", authRoutes); // 🔥 "/auth" 경로로 API 추가

// 기본 라우트
app.get("/", (req, res) => {
  res.send("🚀 Server is running!");
});

// 서버 실행
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
