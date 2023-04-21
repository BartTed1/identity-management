import express from 'express';
import UserController from "../controllers/userController.js";
const router = express.Router();


router.post("/api/v1/auth/register", UserController.isUserExist, UserController.register);
export default router;