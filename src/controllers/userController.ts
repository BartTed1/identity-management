
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
			const userByEmail = await User.getUserByEmail(email);
			const userByUsername = await User.getUserByUsername(username);
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

	public static async authenticate(req: Request, res: Response, next: Function) {
		const { login, password } = req.body;
		if (!login || !password) return res.status(400).send("Missing arguments");
		else if (typeof login !== "string" || typeof password !== "string") return res.status(400).send("Invalid arguments type");

		// username and email check
		let user;
		try {
			const userByEmail = await User.getUserByEmail(login);
			if (!userByEmail) {
				const userByUsername = await User.getUserByUsername(login);
				if (!userByUsername) throw new TypeError("The user with the given username or email does not exist");
				user = userByUsername;
			}
			else {
				user = userByEmail;
			}
			if (!user) throw new TypeError("The user with the given username or email does not exist");
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).send(err.message);
			}
			else {
				return res.status(500).send("Internal server error");
			}
		}

		// password check
		bcrypt.compare(password, user.password, (err, result) => {
			if (err) return res.status(500).send("Internal server error");
			if (result) {
				const token = jwt.sign({
					id: user.id,
					username: user.username,
					role: user.role,
					ip: req.ip // using token from another ip will invalidate it
				},
					process.env.APP_SECRET);
				return res.status(200).send(token);
			}
			else res.status(400).send("Invalid password");
		});
	}
}