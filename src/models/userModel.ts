import {Column, Entity, PrimaryGeneratedColumn} from "typeorm";
import AppDataSource from "../db.js";

@Entity("users")
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    username: string;

    @Column()
    password: string;

    @Column()
    email: string;

    @Column()
    role: string;
    constructor(username: string, password: string, email: string, role: string) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
    }

    public async save() {
        const user = await AppDataSource.manager.findOneBy(User, { username: this.username });
        if (user) return Promise.reject(new TypeError("Username already exists"));
        try {
            await AppDataSource.manager.save(this);
        } catch (err) {
            return Promise.reject(new TypeError("Invalid arguments"));
        }

    }
}