import app from "./app.js";
import dbConnection from "./db.js";

app.set("port", process.env.PORT || 8000);

const server = app.listen(app.get("port"), () => {
	console.log(`Express running → PORT ${app.get("port")}`);
});