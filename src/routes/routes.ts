import express from 'express';
import {User} from "../models/userModel.js";
import bcrypt from "bcrypt";
import UserController from "../controllers/userController.js";
const router = express.Router();


router.post("/api/v1/auth/register", UserController.isUserExist, UserController.register);
router.post("/api/v1/auth/authenticate", (req, res) => {
    res.send('Hello whoever you are');
});
router.post("/api/v1/auth/autorize", (req, res) => {
    res.send('Hello what permissions do you have?');
});
router.get("/api/v1/auth/salt", async (req, res) => {
    bcrypt.genSalt(10, (err, salt) => {
        if (err) return;
        else console.log(salt);
    });
});
export default router;