import { LoginData, LoginProviderEnum } from '../LoginData';
import { UserSession } from "../user/UserSession";
import { LogoutData } from "./LogoutData";
import { User } from 'aws-sdk/clients/workdocs';
import { LoginProviderUser } from './LoginProviderUser';

export interface LoginProvider {
  getUser(loginData: LoginData): Promise<LoginProviderUser>;
  refresh(accessToken: string): Promise<UserSession>;
  logout(logoutData: LogoutData): Promise<void>;
}