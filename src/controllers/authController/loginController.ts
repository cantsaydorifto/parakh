import type { Response, Request } from "express";
import prisma from "../../prisma";
import z from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

function getUserLoginInfoSchema() {
  return z.object({
    username: z
      .string({ required_error: "Username cant be empty" })
      .min(6, "Username should be atleast 6 characters long"),
    password: z
      .string({ required_error: "Password cant be empty" })
      .min(8, "Password must be atleast 8 characters long"),
  });
}

interface User {
  username: string;
  password: string;
}

export const loginController = async (
  req: Request<{}, {}, User>,
  res: Response
) => {
  try {
    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET)
      throw { status: 500, message: "JWT SECRET NOT FOUND" };
    const userInfo = getUserLoginInfoSchema().safeParse(req.body);

    if (!userInfo.success)
      throw { status: 400, message: userInfo.error.issues[0].message };

    const user = await prisma.user.findUnique({
      where: {
        username: userInfo.data.username,
      },
    });

    if (!user) throw { status: 401, message: "User Does Not Exist" };

    const compare = await bcrypt.compare(userInfo.data.password, user.password);
    if (!compare) throw { status: 401, message: "Incorrect Password" };

    const accessToken = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "15min" }
    );

    let refreshToken = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
      },
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
    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
      },
    });

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    });
    res.status(200).json({
      token: accessToken,
      username: user.username,
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    });
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
