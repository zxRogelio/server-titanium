// utils/sendEmailBrevo.js
import pkg from 'sib-api-v3-sdk';
const SibApiV3Sdk = pkg;

import dotenv from 'dotenv';
dotenv.config();

// Configuración del cliente de Brevo
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
const apiKey = SibApiV3Sdk.ApiClient.instance.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY;

// 🟦 Enviar código OTP
export const sendOTP = async (email, otpCode) => {
  try {
    const emailData = {
      to: [{ email }],
      sender: { name: 'Crack Recuperación', email: 'loscracksdelchat@gmail.com' },
      subject: 'Tu código de verificación',
      htmlContent: `
        <h2>Tu código de verificación</h2>
        <p>Usa este código para continuar con tu acceso o recuperación:</p>
        <h1 style="font-size:28px;letter-spacing:2px;">${otpCode}</h1>
        <p>Este código expira en 10 minutos.</p>
      `,
    };

    await apiInstance.sendTransacEmail(emailData);
    console.log(`✅ OTP enviado a ${email}`);
  } catch (error) {
    console.error('❌ Error al enviar OTP con Brevo:', error.response?.text || error.message);
    throw error;
  }
};

// 🟩 Enviar confirmación de acceso tipo "¿Eres tú?"
export const sendConfirmationEmail = async (email, token) => {
  const confirmLink = `http://localhost:5173/confirm-access?token=${token}`;

  try {
    const emailData = {
      to: [{ email }],
      sender: { name: 'UMISUMI Auth', email: 'loscracksdelchat@gmail.com' },
      subject: '¿Eres tú? Confirma tu acceso',
      htmlContent: `
        <h2>Confirmación de acceso</h2>
        <p>Se detectó un intento de inicio de sesión.</p>
        <p>Si fuiste tú, haz clic aquí:</p>
        <a href="${confirmLink}"
          style="display:inline-block;padding:10px 20px;background:#3f51b5;color:#fff;
                 border-radius:6px;text-decoration:none;font-weight:bold;">
          Sí, soy yo
        </a>
        <p>Este enlace expira en 10 minutos.</p>
      `,
    };

    await apiInstance.sendTransacEmail(emailData);
    console.log(`✅ Correo de confirmación enviado a ${email}`);
  } catch (error) {
    console.error('❌ Error al enviar correo de confirmación:', error.response?.text || error.message);
    throw error;
  }
};
