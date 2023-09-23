import { type NextFunction, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import prisma from "../prisma";

export const verifyJwt = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const cookie = req.cookies;
  console.log("verfiytoken");
  try {
    if (!process.env.JWT_SECRET) throw { message: "JWT SECRET NOT FOUND" };
    const refreshToken = cookie.jwt as string;

    const userRefreshToken = await prisma.refreshToken.findUnique({
      where: {
        token: refreshToken,
      },
    });

    if (!userRefreshToken) {
      await prisma.refreshToken.delete({
        where: {
          token: refreshToken,
        },
      });
      res.clearCookie("jwt", { httpOnly: true, secure: true });
      return res.sendStatus(204);
    }
    const authHeader = req.headers["authorization"];
    if (!authHeader) throw { status: 401, message: "Unauthorized" };
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err) => {
      if (err) throw { status: 403, message: "Invalid Token" };
      next();
    });
  } catch (err: any) {
    res
      .status(err.status || 400)
      .json({ message: err.message || err || "ERROR" });
  }
};

export default verifyJwt;
