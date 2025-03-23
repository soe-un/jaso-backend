import nodemailer from "nodemailer";
import { config } from "../config";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
});

export const sendVerificationEmail = async (email: string, token: string) => {
  const verificationLink = `${config.server.url}/auth/verify-email/${token}`;

  const mailOptions = {
    from: config.email.user,
    to: email,
    subject: "이메일 인증을 완료하세요",
    html: `<p>회원가입을 완료하려면 아래 링크를 클릭하세요:</p>
           <a href="${verificationLink}">${verificationLink}</a>`,
  };

  await transporter.sendMail(mailOptions);
};

export const sendResetPasswordEmail = async (email: string, token: string) => {
  const resetLink = `${config.server.url}/auth/reset-password/${token}`; // TODO: 프론트 연결 해야함

  const mailOptions = {
    from: config.email.user,
    to: email,
    subject: "비밀번호 재설정 링크입니다",
    html: `<p>비밀번호를 재설정하려면 아래 링크를 클릭하세요:</p>
             <a href="${resetLink}">${resetLink}</a><br />
             <small>이 링크는 1시간 동안만 유효합니다.</small>`,
  };

  await transporter.sendMail(mailOptions);
};
