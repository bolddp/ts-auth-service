import { User } from "./User";
export interface UserRepository {
    put(user: User): Promise<void>;
    getAll(): Promise<User[]>;
    getByUserName(userName: string): Promise<User>;
    delete(userName: string): Promise<void>;
}
