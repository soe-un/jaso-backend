import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/user";
import { config } from "./config";

dotenv.config();

const app = express();
const PORT = config.server.port;

// Middleware
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// API 라우트
app.use("/auth", authRoutes);
app.use("/user", userRoutes);

// 기본 라우트
app.get("/", (req, res) => {
  res.send("🚀 Server is running!");
});

// 서버 실행
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
