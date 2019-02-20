import { UserRepository } from "../../src/user/UserRepository";
import { User } from "../../src/user/User";

export class InMemoryUserRepository implements UserRepository {
  user: User;

  put(user: User) : Promise<void> {
    this.user = user;
    return Promise.resolve();
  }

  getAll(): Promise<User[]> {
    return Promise.resolve([ this.user ]);
  }

  getByUserName(userName: string) : Promise<User> {
    return Promise.resolve(this.user);
  }

  delete(userName: string): Promise<void> {
    this.user = undefined;
    return Promise.resolve();
  }
}