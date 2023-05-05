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

    /***
     * Saves the user in the database
     */
    public async save() {
        try {
            await AppDataSource.manager.save(this);
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    /***
     * Returns the user with the given email
     * @param email Email of the user
     */
    public static async getUserByEmail(email: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{email: email});
            if (user) return user;
            return null;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    /***
     * Returns the user with the given username
     * @param username Username of the user
     */
    public static async getUserByUsername(username: string) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{username: username});
            if (user) return user;
            return null;
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

    /***
     * Verifies if the user has the given permission
     * @param userId ID of the user
     * @param permission Permission to check
     */
    public static async verifyPermission(userId: number, permission: Permissions) {
        try {
            const user = await AppDataSource.manager.findOneBy(User,{id: userId});
            return !!user.permissions.includes(permission);

        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }
    }

}