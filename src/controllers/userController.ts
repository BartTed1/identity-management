
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User, Permissions } from "../models/userModel.js";

export default class UserController {
	public static async register(req: Request, res: Response, next: Function) {
		const { username, password, email } = req.body;
		if (!username || !password || !email) return res.status(400).send("Missing arguments");
		else if (typeof username !== "string" || typeof password !== "string" || typeof email !== "string") return res.status(400).send("Invalid arguments type");
		try {
			const salt = await bcrypt.genSalt(10);
			const hashedPassword = await bcrypt.hash(password, salt);
			const user = new User(username, hashedPassword, email, [Permissions.WRITE270, Permissions.DELETE]); // default permissions
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
					ip: req.ip // using token from another ip will invalidate it
				},
					process.env.APP_SECRET);
				return res.status(200).send(token);
			}
			else res.status(400).send("Invalid password");
		});
	}

	public static async verify(req: Request, res: Response, next: Function) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).send("Unauthenticated");
		jwt.verify(token, process.env.APP_SECRET, (err, decoded) => {
			if (err) return res.status(401).send("Unauthenticated");
			if (decoded.ip !== req.ip) return res.status(401).send("Unauthenticated");

			const issuedAt = decoded.iat * 1000;
			const now = new Date();
			const expireIn = parseInt(process.env.TOKEN_EXPIREIN);
			if (issuedAt + expireIn <= now.getTime()) {
				return res.status(401).send("Unauthenticated - token expired");
			}
			else return next();
		});
	}

	public static async refresh(req: Request, res: Response) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).send("Unauthenticated");
		jwt.verify(token, process.env.APP_SECRET, (err, decoded) => {
			if (err) return res.status(401).send("Unauthenticated");
			if (decoded.ip !== req.ip) return res.status(401).send("Unauthenticated");
			const issuedAt = decoded.iat * 1000;
			const now = new Date();
			const expireIn = parseInt(process.env.TOKEN_EXPIREIN);
			const timeLeft = issuedAt + expireIn - now.getTime();
			const refreshTime = parseInt(process.env.TOKEN_REFRESH);

			if (issuedAt + expireIn <= now.getTime()) {
				return res.status(401).send("Unauthenticated - token expired");
			}
			else if (timeLeft > refreshTime) {
				return res.status(401).send("Token can't be refreshed yet");
			}

			const token = jwt.sign({
					id: decoded.id,
					username: decoded.username,
					ip: req.ip // using token from another ip will invalidate it
				},
				process.env.APP_SECRET);
			return res.status(200).send(token);
		});
	}
}