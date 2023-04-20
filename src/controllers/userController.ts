
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User } from "../models/userModel.js";

export default class UserController {

	// public static async register(username: string, password: string, email: string, role: string);
	// public static async register(user: User);
	// public static async register(arg1: any, arg2?: any, arg3?: any, arg4?: any) {
	// 	try {
	// 		if (arg1 instanceof User) {
	// 			await arg1.save();
	// 		} else if (typeof arg1 === "string") {
	// 			if (typeof arg2 !== "string" || typeof arg3 !== "string" || typeof arg4 !== "string") throw new TypeError("Invalid arguments type");
	// 			const user = new User(arg1, arg2, arg3, arg4);
	// 			await user.save();
	// 		}
	// 		else throw new TypeError("Invalid arguments");
	// 	} catch (err) {
	// 		return Promise.reject(err);
	// 	}
	// }

	public static async register(req: Request, res: Response) {
		const { username, password, email, role } = req.body;
		if (!username || !password || !email || !role) return res.status(400).send("Missing arguments");
		else if (typeof username !== "string" || typeof password !== "string" || typeof email !== "string" || typeof role !== "string") return res.status(400).send("Invalid arguments type");
		try {
			const user = new User(username, password, email, role);
			await user.save();
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).send(err.message);
			}
			else {
				return res.status(500).send("Internal server error");
			}
		}
		return res.status(200).send("User registered");
	}
}