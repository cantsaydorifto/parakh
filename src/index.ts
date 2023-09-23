import express from "express";
import logout from "./routes/logout";
import user from "./routes/user";
import refresh from "./routes/refresh";
import cookieParser from "cookie-parser";
import { verifyJwt } from "./middleware/verifyJwt";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/api/user", user);
app.use("/api/refresh", refresh);
app.use(verifyJwt);
app.use("/api/logout", logout);

app.listen(process.env.PORT, () => {
  console.log("Listening on port " + process.env.PORT);
});
