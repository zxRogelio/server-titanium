// validateRegister.js
import { body, validationResult } from 'express-validator';
import sanitizeHtml from 'sanitize-html';

export const validateRegister = [
  body('email').isEmail().withMessage('Correo inválido'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('La contraseña debe tener mínimo 8 caracteres')
    .matches(/[a-z]/).withMessage('Debe incluir minúsculas')
    .matches(/[A-Z]/).withMessage('Debe incluir mayúsculas')
    .matches(/[0-9]/).withMessage('Debe incluir un número')
    .matches(/[\W]/).withMessage('Debe incluir un símbolo'),
  (req, res, next) => {
    // Sanitizar entradas
    for (let field in req.body) {
      if (typeof req.body[field] === 'string') {
        req.body[field] = sanitizeHtml(req.body[field]);
      }
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];