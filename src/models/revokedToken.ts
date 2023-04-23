import {Entity, PrimaryColumn} from "typeorm";
import AppDataSource from "../db.js";

@Entity("revokedTokens")
export class RevokedToken {
	@PrimaryColumn()
	token: string;

	constructor(token: string) {
		this.token = token;
	}

	public async revoke() {
		try {
			await AppDataSource.manager.save(this);
		} catch (err) {
			return Promise.reject(new TypeError("Invalid arguments"));
		}
	}

	public static async isTokenRevoked(token: string) {
		try {
			const revokedToken = await AppDataSource.manager.findOneBy(RevokedToken,{token: token});
			if (revokedToken) return true;
			return false;
		} catch (err) {
			return Promise.reject(new TypeError("Invalid arguments"));
		}
	}
}