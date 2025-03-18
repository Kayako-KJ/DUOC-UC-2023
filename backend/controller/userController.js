const bcrypt = require("bcrypt");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const registerUser = async (req, res, next) => {
  try {
    let { name, email, password } = req.body;
    password = String(password);
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All inputs are required" });
    }
    const userExist = await User.findOne({ email });
    if (userExist) {
      return res.status(400).json({ message: "User Already Exists." });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await User.create({
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
      });
      res
        .status(201)
        .json({ success: "User registered successfully", user: user });
    }
  } catch (error) {
    console.log("error", error);
    next(error);
  }
};


const loginUser = async (req, res, next) => {
  try {
    let { email, password } = req.body;
    email = email.toLowerCase();
    password = String(password); 
    if (!email || !password) {
      return res.status(400).json({ message: "All inputs are required" });
    }
    const user = await User.findOne({ email });
    if (user) {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const { password, ...userInfo } = user._doc;

        const token = jwt.sign(
          { userId: user._id },
          process.env.JWT_SECRET_KEY,
          {
            expiresIn: "7d",
          }
        );

        res.cookie("token", token, {
          maxAge: 7 * 24 * 60 * 60 * 1000,
          httpOnly: true,
          sameSite: "strict",
        });
        return res.json({
          success: "User Logged in Successfully.",
          userInfo,
          token: token,
        });
      } else {
        return res.status(401).json({ message: "Wrong credentials." });
      }
    } else {
      return res.status(401).json({ message: "User does not exist." });
    }
  } catch (error) {
    next(error);
  }
};


const logoutUser = async (req, res, next) => {
  try {

    res.cookie("token", "", {
      maxAge: 0,
      httpOnly: true,
      sameSite: "strict",
    });
    return res.json({ success: "User Logged out Successfully." });
  } catch (error) {
    next(error);
  }
};


const forgotPassword = async (req, res, next) => {
  try {
    let { email } = req.body;
    email = email.toLowerCase();
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "User does not exist." });
    } else {

      function generateRandomOtp() {
        const chars =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let result = "";
        for (let i = 0; i < 6; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      }
      const otp = generateRandomOtp();

      res.cookie("reset_password_otp", otp, {
        maxAge: 5 * 60 * 1000, 
        httpOnly: true, 
      });

      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || "smtp.ethereal.email",
        port: process.env.SMTP_PORT || 587,
        auth: {
          user: process.env.SMTP_EMAIL || "kavon16@ethereal.email",
          pass: process.env.SMTP_PASSWORD || "bwAFqjrTey9GAd3zzd",
        },
      });
      const mailOptions = {
        from: `"${process.env.EMAIL_SENDER_NAME || "Sushant Kumar"}" <${
          process.env.EMAIL_USERNAME || "sushant@gmail.com"
        }>`,
        to: email,
        subject: "Password Reset OTP",
        text: `Your OTP for resetting password is - ${otp}. It is valid for 5 minutes.`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {

          return res.status(500).json({
            message: "Error sending email.",
            error,
          });
        } else {

          return res.json({
            message: "OTP sent to email.",
            info,
          });
        }
      });
    }
  } catch (error) {
    next(error);
  }
};


const resetPassword = async (req, res, next) => {
  try {
    let { email, otp, newPassword } = req.body;
    email = email.toLowerCase();
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "All inputs are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "User does not exist." });
    }

    const resetPasswordOTP = req.cookies.reset_password_otp;

    if (!resetPasswordOTP || resetPasswordOTP !== otp) {
      return res.status(401).json({ message: "Invalid OTP" });
    }


    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    user.password = hashedPassword;
    await user.save();

    res.clearCookie("reset_password_otp");

    return res.status(200).json({ message: "Password reset successful." });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  forgotPassword,
  resetPassword,
};
