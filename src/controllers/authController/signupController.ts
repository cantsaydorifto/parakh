import type { Response, Request } from "express";
import prisma from "../../prisma";
import z from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

interface User {
  username: string;
  password: string;
  email: string;
}

function getUserSingupInfoSchema() {
  return z.object({
    username: z
      .string({ required_error: "Username cant be empty" })
      .min(6, "Username should be atleast 6 characters long"),

    email: z
      .string({ required_error: "Email cant be empty" })
      .email("Not a valid email"),

    password: z
      .string({ required_error: "Password cant be empty" })
      .min(8, "Password must be atleast 8 characters long"),
    firstName: z.string({ required_error: "First Name is Required" }),
    lastName: z.string({ required_error: "Last Name is Required" }),
    // dateOfBirth: z.date({ required_error: "Date of birth is Required" }),
  });
}

export const signupController = async (
  req: Request<{}, {}, User>,
  res: Response
) => {
  try {
    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET)
      throw { status: 500, message: "JWT SECRET NOT FOUND" };
    const userInfo = getUserSingupInfoSchema().safeParse(req.body);

    if (!userInfo.success)
      throw { status: 400, message: userInfo.error.issues[0].message };

    const userUsername = await prisma.user.findUnique({
      where: {
        username: userInfo.data.username,
      },
    });
    const userEmail = await prisma.user.findUnique({
      where: {
        email: userInfo.data.email,
      },
    });

    if (userUsername) throw { status: 401, message: "username already in use" };
    if (userEmail) throw { status: 401, message: "email already in use" };

    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(userInfo.data.password, salt);

    let refreshToken = jwt.sign(
      { username: userInfo.data.username },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "4d" }
    );
    const isTokenInUse = await checkToken(refreshToken);

    if (isTokenInUse) {
      refreshToken = jwt.sign(
        { username: userInfo.data.username },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "4d" }
      );
    }

    const user = await prisma.user.create({
      data: {
        email: userInfo.data.email,
        password: hash,
        username: userInfo.data.username,
        firstName: userInfo.data.firstName,
        lastName: userInfo.data.lastName,
        RefreshToken: {
          create: {
            token: refreshToken,
          },
        },
      },
    });

    const accessToken = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "15min" }
    );

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    });
    res.status(200).json({ token: accessToken });
  } catch (err: any) {
    res
      .status(err.status || 400)
      .json({ message: err.message || err || "ERROR" });
  }
};

async function checkToken(token: string) {
  const res = await prisma.refreshToken.findUnique({
    where: {
      token,
    },
  });
  return !!res;
}
