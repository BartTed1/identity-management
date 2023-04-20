import express from 'express';
import {User} from "../models/userModel.js";
import UserController from "../controllers/userController.js";
const router = express.Router();


router.post("/api/v1/auth/register", UserController.register);
router.post("/api/v1/auth/authenticate", (req, res) => {
    res.send('Hello whoever you are');
});

router.post("/api/v1/auth/autorize", (req, res) => {
    res.send('Hello what permissions do you have?');
});
export default router;