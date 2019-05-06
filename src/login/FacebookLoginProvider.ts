import * as crypto from 'crypto';
import { LoginProvider } from "./LoginProvider";
import { LoginData, LoginProviderEnum } from "../LoginData";
import { LogoutData } from "./LogoutData";
import { UserSession } from "../user/UserSession";
import { FacebookConfig } from "../auth/AwsAuthServiceConfig";
import { AuthError } from '../auth/AuthError';
import { LoginProviderUser } from "./LoginProviderUser";

export class FacebookLoginProvider implements LoginProvider {
  config: FacebookConfig;

  constructor(config: FacebookConfig) {
    this.config = config;
  }

  private createPermanentPassword(userName: string): string {
    return crypto.createHash('sha1').update(`fbpwd_${userName}`).digest('hex');
  }

  async getUser(loginData: LoginData): Promise<LoginProviderUser> {
    if (!loginData.accessToken) {
      throw AuthError.AccessTokenNotFound;
    }
    const token = loginData.accessToken!;
    const longLivedTokenInfo = await fetch(`https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=${this.config.appId}&client_secret=${this.config.appSecret}&fb_exchange_token=${token}`)
      .then(response => response.json());

    const userInfo = await fetch(`https://graph.facebook.com/me?access_token=${token}&fields=id,email,first_name,last_name`)
      .then(response => response.json());

    const userName = `${LoginProviderEnum.Facebook}_${longLivedTokenInfo.id}`;
    return <LoginProviderUser>{
      userName,
      permanentPassword: this.createPermanentPassword(userName),
      loginProvider: LoginProviderEnum.Facebook,
      email: decodeURI(userInfo.email),
      firstName: decodeURI(userInfo.first_name),
      lastName: decodeURI(userInfo.last_name),
      accessToken: longLivedTokenInfo.access_token,
      accessTokenExpiry: new Date().getTime() + (longLivedTokenInfo.expires_in * 1000)
    };
  }

  async refresh(accessToken: string): Promise<UserSession> {
    return null;
  }

  async logout(logoutData: LogoutData): Promise<void> {

  }
}