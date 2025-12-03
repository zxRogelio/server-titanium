import helmet from "helmet";

export const secureHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: {
    action: "deny",
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
});
