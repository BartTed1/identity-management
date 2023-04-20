import { config } from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import routes from "./routes/routes.js";

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use("/", routes);

app.use((req, res, next) => {
	res.sendStatus(404);
});

export default app;