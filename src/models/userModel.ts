import {Column, Entity, PrimaryGeneratedColumn} from "typeorm";
import AppDataSource from "../db.js";

@Entity("users")
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    username: string;

    @Column({length: 60})
    password: string;

    @Column()
    email: string;

    @Column()
    role: string;

    @Column({length: 29})
    salt: string;

    constructor(username: string, password: string, email: string, role: string, salt: string) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.salt = salt;
    }

    public async save() {
        try {
            await AppDataSource.manager.save(this);
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    public static async isEmailExist(email: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{email: email});
            if (user) return true;
            return false;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    public static async isUsernameExist(username: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{username: username});
            if (user) return true;
            return false;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

}