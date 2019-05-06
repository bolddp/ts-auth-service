import { LoginProviderEnum } from "../LoginData";

export interface LogoutData {
  loginProvider: LoginProviderEnum;
  accessToken: string;
}