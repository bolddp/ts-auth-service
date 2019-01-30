import { SignupData } from "../SignupData";
import { UserSession } from "../user/UserSession";
import { LoginData } from "../LoginData";
export interface AuthService {
    signup(signupData: SignupData): Promise<void>;
    login(loginData: LoginData): Promise<UserSession>;
    refresh(authHeader: string): Promise<UserSession>;
    deleteUser(userName: string): Promise<void>;
}
