import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  otp: { type: String },
  otpExpires: { type: Date },
  isPendingApproval: { type: Boolean, default: false },
  accessToken: { type: String, default: null },
  totpSecret: { type: String, default: null },

});

export const User = mongoose.model("User", userSchema);
