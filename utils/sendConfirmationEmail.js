import { Resend } from "resend";
import dotenv from "dotenv";
dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendConfirmationEmail = async (email, token) => {
  const confirmLink = `http://localhost:5173/confirm-access?token=${token}`;

  const { error } = await resend.emails.send({
    from: "UMISUMI <onboarding@resend.dev>",
    to: email,
    subject: "¿Eres tú?",
    html: `
      <h2>Confirmación de acceso</h2>
      <p>Alguien intentó iniciar sesión. Si fuiste tú, confirma:</p>
      <a href="${confirmLink}" style="padding:10px;background:#3f51b5;color:white;border-radius:5px;text-decoration:none;">Sí, soy yo</a>
      <p>Este enlace expira en 10 minutos.</p>
    `,
  });

  if (error) throw error;
};
