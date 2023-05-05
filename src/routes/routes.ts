import express from 'express';
import UserController from "../controllers/userController.js";
const router = express.Router();

router.post("/api/v1/auth/register", UserController.isUserExist, UserController.register);

router.post("/api/v1/auth/authenticate", UserController.authenticate);

router.post("/api/v1/auth/verify", UserController.verify, (req, res) => {
	res.status(200).send("Authenticated");
});

router.post("/api/v1/auth/refresh", UserController.refresh);

router.post("/api/v1/auth/revoke", UserController.revoke); // like logout


export default router;