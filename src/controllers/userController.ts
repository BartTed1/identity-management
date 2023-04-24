
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User, Permissions } from "../models/userModel.js";
import {RevokedToken} from "../models/revokedToken.js";

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
			if (userByEmail || userByUsername) return res.status(400).send(`The user with the given: ${userByEmail ? "email" : ""} ${userByUsername ? "username" : ""} already exists`);
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
				if (!userByUsername) return res.status(400).send("The user with the given username or email does not exist");
				user = userByUsername;
			}
			else {
				user = userByEmail;
			}
			if (!user) return res.status(400).send("The user with the given username or email does not exist");
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
				const newToken = jwt.sign({
					id: user.id,
					username: user.username,
					ip: req.ip // using token from another ip will invalidate it
				},
					process.env.APP_SECRET);
				return res.status(200).cookie("token", newToken, {httpOnly: true, secure: true, sameSite: "strict", maxAge: parseInt(process.env.TOKEN_EXPIREIN) + 1}).json({message: "Token created"});
			}
			else res.status(400).json({error: "Invalid password"});
		});
	}

	private static async verifyToken(token: string, ip: string): Promise<{token: any, refreshable: boolean}> {
		return new Promise(async (resolve, reject) => {
			// is token revoked?
			const revokedToken = await RevokedToken.isTokenRevoked(token);
			if (revokedToken) return reject(new Error("Token revoked"));

			// is token valid?
			jwt.verify(token, process.env.APP_SECRET, (err, decoded) => {
				if (err) return reject(new Error("Invalid Token"));
				if (decoded.ip !== ip) {
					const revokedToken = new RevokedToken(token);
					revokedToken.revoke();
					return reject(new Error("Token revoked"));
				}
				const issuedAt = decoded.iat * 1000;
				const now = new Date();
				const expireIn = parseInt(process.env.TOKEN_EXPIREIN);
				const timeLeft = issuedAt + expireIn - now.getTime();
				const refreshTime = parseInt(process.env.TOKEN_REFRESH);

				// is token expired?
				if (timeLeft <= 0) return reject(new Error("Token expired"));

				const result = {
					token: decoded,
					refreshable: timeLeft < refreshTime // if timeLeft is less than refreshTime, token is refreshable
				}
				return resolve(result);
			});
		});
	}

	public static async verify(req: Request, res: Response, next: Function) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).json({error: "Token must be provided"});
		if (typeof token !== "string") return res.status(400).json({error: "Token must be a string"});

		try {
			await UserController.verifyToken(token, req.ip);
		} catch (err) {
			return res.status(401).json({error: err.message});
		}
		return next();
	}

	public static async refresh(req: Request, res: Response) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).json({error: "Token must be provided"});
		if (typeof token !== "string") return res.status(400).json({error: "Token must be a string"});

		try {
			const result = await UserController.verifyToken(token, req.ip);
			if (!result.refreshable) return res.status(400).json({error: "Unauthenticated - token not refreshable"});
			const newToken = jwt.sign({
				id: result.token.id,
				username: result.token.username,
				ip: req.ip
			}, process.env.APP_SECRET);
			return res.status(200).cookie("token", newToken, {httpOnly: true, secure: true, sameSite: "strict", maxAge:  parseInt(process.env.TOKEN_EXPIREIN) + 1}).json({message: "Token created"});
		} catch (err) {
			return res.status(401).json({error: err.message});
		}
	}

	public static async revoke(req: Request, res: Response) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).json({error: "Token must be provided"});
		if (typeof token !== "string") return res.status(400).json({error: "Token must be a string"});
		try {
			await UserController.verifyToken(token, req.ip);
			const revokedToken = new RevokedToken(token);
			await revokedToken.revoke();
			return res.status(200).json({error: "Token revoked"});
		} catch (err) {
			return res.status(401).json({error: err.message});
		}
	}
}