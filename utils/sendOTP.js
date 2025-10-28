import { Resend } from "resend";
import dotenv from "dotenv";
dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendOTP = async (email, otpCode) => {
  try {
    const { data, error } = await resend.emails.send({
      from: "UMISUMI <onboarding@resend.dev>", // ✅ puedes usar este por defecto
      to: email,
      subject: "Tu código de verificación",
      html: `<h1>${otpCode}</h1><p>Este código expira en 10 minutos.</p>`,
    });

    if (error) {
      console.error("Error al enviar correo:", error);
      throw error;
    }

    console.log("✅ Correo enviado:", data.id);
  } catch (err) {
    console.error("❌ Error en envío con Resend:", err);
    throw err;
  }
};



/*
import nodemailer from "nodemailer";

export const sendOTP = async (email, otpCode) => {
  const transporter = nodemailer.createTransport({
    host: "smtp-relay.brevo.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.BREVO_USER,
      pass: process.env.BREVO_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  await transporter.sendMail({
    from: `"Crack Recuperación" <${process.env.BREVO_USER}>`,
    to: email,
    subject: "Tu código de verificación",
    html: `<h1>${otpCode}</h1><p>Este código expira en 10 minutos.</p>`,
  });
};
*/