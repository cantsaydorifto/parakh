import express from "express";
import logout from "./routes/logout";
import user from "./routes/user";
import refresh from "./routes/refresh";
import cookieParser from "cookie-parser";
import { verifyJwt } from "./middleware/verifyJwt";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const app = express();

app.use(cors({ credentials: true, origin: process.env.BASE_URL_FRONTEND }));

app.use(express.json());
app.use(cookieParser());

app.use("/user", user);
app.use("/refresh", refresh);
app.use(verifyJwt);
app.use("/logout", logout);

app.listen(process.env.PORT, () => {
  console.log("Listening on port " + process.env.PORT);
});
