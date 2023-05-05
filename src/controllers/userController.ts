import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { User, Permissions } from "../models/userModel.js";
import {RevokedToken} from "../models/revokedToken.js";

export default class UserController {
	/***
	 * Register new user
	 * @static
	 * @param req {Request} Request object
	 * @param res {Response} Response object
	 * @returns {Response} Next function or HTTP error
	 * @memberOf UserController
	 */
	public static async register(req: Request, res: Response) {
		const { username, password, email } = req.body;
		if (!username || !password || !email) return res.status(400).json({error: "Missing arguments"});
		else if (typeof username !== "string" || typeof password !== "string" || typeof email !== "string") return res.status(400).json({error: "Invalid arguments type"});
		try {
			const salt = await bcrypt.genSalt(10);
			const hashedPassword = await bcrypt.hash(password, salt);
			const user = new User(username, hashedPassword, email, [Permissions.WRITE270, Permissions.DELETE]); // default permissions
			await user.save();
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).json({error: err.message});
			}
			else {
				return res.status(500).json({error: "Internal server error"});
			}
		}
		return res.status(200).json({message: "User registered"});
	}

	/***
	 * Is user exist
	 * @static
	 * @param req {Request} Request object
	 * @param res {Response} Response object
	 * @param next {Function} Next function
	 * @returns {function|Response} Next function or HTTP error
	 * @memberOf UserController
	 */
	public static async isUserExist(req: Request, res: Response, next: Function) {
		try {
			const { username, email } = req.body;
			const userByEmail = await User.getUserByEmail(email);
			const userByUsername = await User.getUserByUsername(username);
			if (userByEmail || userByUsername) return res.status(400).json({error: `The user with the given: ${userByEmail ? "email" : ""} ${userByUsername ? "username" : ""} already exists`});
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).json({error: err.message});
			}
			else {
				return res.status(500).json({error: "Internal server error"});
			}
		}
		return next();
	}

	/***
	 * Authenticates the user
	 * @static
	 * @param req {Request} Request object
	 * @param res {Response} Response object
	 * @returns {Response} Response object
	 * @memberof UserController
	 */
	public static async authenticate(req: Request, res: Response) {
		const { login, password } = req.body;
		if (!login || !password) return res.status(400).json({error: "Missing arguments"});
		else if (typeof login !== "string" || typeof password !== "string") return res.status(400).json({error: "Invalid arguments type"});

		// username and email check
		let user;
		try {
			const userByEmail = await User.getUserByEmail(login);
			if (!userByEmail) {
				const userByUsername = await User.getUserByUsername(login);
				if (!userByUsername) return res.status(400).json({error: "The user with the given username or email does not exist"});
				user = userByUsername;
			}
			else {
				user = userByEmail;
			}
			if (!user) return res.status(400).json({error: "The user with the given username or email does not exist"});
		} catch (err) {
			if (err instanceof TypeError) {
				return res.status(400).json({error: err.message});
			}
			else {
				return res.status(500).json({error: "Internal server error"});
			}
		}

		// password check
		bcrypt.compare(password, user.password, (err, result) => {
			if (err) return res.status(500).json({error: "Internal server error"});
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

	/***
	 * Verify JWT token
	 * @private
	 * @static
	 * @param {string} token JWT token
	 * @param {string} ip IP address of the request
	 * @returns {Promise<{token: any, refreshable: boolean}>} Returns decoded token and if it is refreshable
	 * @memberof UserController
	 * @throws {Error} If token is invalid, expired or revoked
	 */
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

	/***
	 * Verify JWT token
	 * @static
	 * @param {Request} req Request object
	 * @param {Response} res Response object
	 * @param {Function} next Next function
	 * @memberof UserController
	 * @returns {function|Response} Returns next function or HTTP error
	 */
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

	/***
	 * Refresh JWT token
	 * @static
	 * @param {Request} req Request object
	 * @param {Response} res Response object
	 * @memberof UserController
	 * @returns {Response} Returns HTTP response
	 */
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

	/***
	 * Revoke token (logout), given token can't be used anymore
	 * @static
	 * @param {Request} req Request object
	 * @param {Response} res Response object
	 * @memberof UserController
	 * @returns {Response} Returns HTTP response
	 */
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

	/***
	 * Check if user has permission.
	 *
	 * The user is authenticated based on the token
	 * @static
	 * @param {Request} req Request object
	 * @param {Response} res Response object
	 * @param {Permissions} permission Permission to check
	 * @param {Function} next Next function
	 * @memberof UserController
	 * @returns {function|Response} Returns next function or HTTP error
	 */
	public static async authorize(req: Request, res: Response, permission: Permissions, next: Function) {
		const token = req.headers["authorization"];
		if (!token) return res.status(400).json({error: "Token must be provided"});
		if (typeof token !== "string") return res.status(400).json({error: "Token must be a string"});
		try {
			const result = await this.verifyToken(token, req.ip);
			const hasPermission = await User.verifyPermission(result.token.id, permission);
			if (!hasPermission) return res.status(401).json({error: "Unauthorized"});
			return next();
		} catch (err) {
			return res.status(401).json({error: err.message});
		}
	}
}