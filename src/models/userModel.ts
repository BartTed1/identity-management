import {Column, Entity, PrimaryGeneratedColumn} from "typeorm";
import AppDataSource from "../db.js";

export enum Permissions {
    WRITE270 = "write270",
    WRITE2000 = "write2000",
    DELETE = "delete",
    MODIFY = "modify"
}

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
    permissions: string;

    constructor(username: string, password: string, email: string, permissions: Permissions[]) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.permissions = permissions ? permissions.join(",") : "";
    }

    public async save() {
        try {
            await AppDataSource.manager.save(this);
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    public static async getUserByEmail(email: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{email: email});
            if (user) return user;
            return null;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    public static async getUserByUsername(username: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{username: username});
            if (user) return user;
            return null;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

}