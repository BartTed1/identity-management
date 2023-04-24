import { createConnection, DataSource } from "typeorm";
import dotenv from "dotenv";

dotenv.config();

describe("AppDataSource", () => {
	it("should initialize successfully", async () => {
		const AppDataSource = new DataSource({
			type: "postgres",
			host: process.env.DB_HOST,
			port: parseInt(process.env.DB_PORT),
			username: process.env.DB_USER,
			password: process.env.DB_PASSWORD,
			database: process.env.DB_NAME,
			entities: ["./models/*.js"],
			synchronize: true
		});

		expect(AppDataSource.manager.connection.isInitialized).toBe(true);
		expect(AppDataSource.initialize).toBe(true);
	});
});
