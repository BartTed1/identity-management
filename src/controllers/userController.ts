
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User } from "../models/userModel.js";
import AppDataSource from "../db.js";

export default class UserController {
	public static async register(req: Request, res: Response, next: Function) {
		const { username, password, email, role } = req.body;
		if (!username || !password || !email || !role) return res.status(400).send("Missing arguments");
		else if (typeof username !== "string" || typeof password !== "string" || typeof email !== "string" || typeof role !== "string") return res.status(400).send("Invalid arguments type");
		try {
			const salt = await bcrypt.genSalt(10);
			const hashedPassword = await bcrypt.hash(password, salt);
			const user = new User(username, hashedPassword, email, role, salt);
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

	public static async isUserExist(req: Request, res: Response, next: Function) {
		try {
			const { username, email } = req.body;
			const userByEmail = await User.isEmailExist(email);
			const userByUsername = await User.isUsernameExist(username);
			if (userByEmail || userByUsername) throw new TypeError(`The user with the given: ${userByEmail ? "email" : ""} ${userByUsername ? "username" : ""} already exists`);
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).send(err.message);
			}
			else {
				return res.status(500).send("Internal server error");
			}
		}
		return next();
	}
}