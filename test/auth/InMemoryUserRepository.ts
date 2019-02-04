import { UserRepository } from "../../src/user/UserRepository";
import { User } from "../../src/user/User";

export class InMemoryUserRepository implements UserRepository {
  users: User[] = [];

  put(user: User) : Promise<void> {
    this.users.push(user);
    return Promise.resolve();
  }

  getAll() {
    return Promise.resolve(this.users);
  }

  getByUserName(userName: string) : Promise<User> {
    return Promise.resolve(this.users.find(x => x.userName == userName));
  }

  delete(userName: string): Promise<void> {
    const index = this.users.findIndex(x => x.userName == userName);
    if (index >= 0) {
      this.users.splice(index, 1);
    }
    return Promise.resolve();
  }
}