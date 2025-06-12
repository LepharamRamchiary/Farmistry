import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/users.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, mobileNumber, password, role } = req.body;

  if (!fullName || !password) {
    throw new ApiError(400, "Full name and password are required");
  }

  if (!email && !mobileNumber) {
    throw new ApiError(400, "Either email or mobile number is required");
  }

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new ApiError(400, "Please provide a valid email address");
  }

  if (mobileNumber && !/^[0-9]{10}$/.test(mobileNumber)) {
    throw new ApiError(400, "Mobile number must be exactly 10 digits");
  }

  if (fullName.length < 3 || fullName.length > 25) {
    throw new ApiError(400, "Full name must be between 3 and 25 characters");
  }

  if (password.length < 6) {
    throw new ApiError(400, "Password must be at least 6 characters");
  }

  if (role && !["farmer", "consumer"].includes(role)) {
    throw new ApiError(400, "Role must be either 'farmer' or 'consumer'");
  }

  let existingUserByEmail = null;
  let existingUserByMobile = null;

  if (email) {
    existingUserByEmail = await User.findOne({ email: email.toLowerCase() });
  }

  if (mobileNumber) {
    existingUserByMobile = await User.findOne({ mobileNumber });
  }

  if (existingUserByEmail) {
    throw new ApiError(
      409,
      "Email is already registered. Please try another email address."
    );
  }

  if (existingUserByMobile) {
    throw new ApiError(
      409,
      "Mobile number is already registered. Please try another mobile number."
    );
  }

  try {
    const newUser = new User({
      fullName: fullName.trim(),
      email: email ? email.toLowerCase().trim() : undefined,
      mobileNumber: mobileNumber ? mobileNumber.trim() : undefined,
      password,
      role: role || "consumer",
    });

    const otpPhone = newUser.generateOTP();
    const otpEmail = newUser.generateOTP();

    await newUser.save();

    // Log OTP (in production, send via SMS/Email service)
    if (email && mobileNumber) {
      //   sendOtpToEmail(email, otpCode);
      //   sendOtpToMobile(mobileNumber, otpCode);
      console.log(
        `OTP sent to email: ${email} : ${otpEmail} and mobile: ${mobileNumber} : ${otpPhone}`
      );
    } else if (email) {
      //   sendOtpToEmail(email, otpCode);
      console.log(`OTP sent to email: ${email} : ${otpEmail}`);
    } else if (mobileNumber) {
      //   sendOtpToMobile(mobileNumber, otpCode);
      console.log(`OTP sent to mobile: ${mobileNumber} : ${otpPhone}`);
    }

    res.status(201).json(
      new ApiResponse(
        201,
        {
          fullName: newUser.fullName,
          email: newUser.email,
          mobileNumber: newUser.mobileNumber,
          role: newUser.role,
          isVerified: newUser.isVerified,
        },
        "User registered successfully. Please verify your account with the OTP sent."
      )
    );
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = Object.values(error.errors).map(
        (err) => err.message
      );
      throw new ApiError(400, "Validation failed", validationErrors);
    }

    if (error.code === 11000) {
      const field = Object.keys(error.keyValue)[0];
      const value = error.keyValue[field];
      throw new ApiError(
        409,
        `${field} '${value}' is already registered. Please try another ${field}.`
      );
    }

    throw new ApiError(500, "Failed to register user. Please try again.");
  }
});

export { registerUser };
