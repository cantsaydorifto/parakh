import type { Response, Request } from "express";
import prisma from "../../prisma";

export const logoutController = async (
  req: Request & {
    user?: {
      id: number;
      username: string;
      email: string;
    };
  },
  res: Response
) => {
  const cookie = req.cookies;
  try {
    if (!cookie.jwt || !req.user)
      throw { status: 401, message: "Unauthorized" };
    console.log(req.user);
    const refreshToken = cookie.jwt as string;
    const userRefreshToken = await prisma.refreshToken.findUnique({
      where: {
        token: refreshToken,
      },
      include: {
        User: {
          select: {
            username: true,
            email: true,
            id: true,
          },
        },
      },
    });
    if (!userRefreshToken) {
      res.clearCookie("jwt", { httpOnly: true, secure: true });
      return res.sendStatus(204);
    }
    await prisma.refreshToken.delete({
      where: {
        token: refreshToken,
      },
    });
    res.clearCookie("jwt", { httpOnly: true, secure: true });
    res.sendStatus(204);
  } catch (err: any) {
    res
      .status(err.status || 400)
      .json({ message: err.message || err || "ERROR" });
  }
};
