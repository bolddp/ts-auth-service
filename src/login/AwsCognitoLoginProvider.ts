import { LoginProvider } from "./LoginProvider";
import { LoginData } from "../LoginData";
import { LogoutData } from "./LogoutData";
import { UserSession } from "../user/UserSession";
import { CognitoConfig } from '../auth/AwsAuthServiceConfig';
import { LoginProviderUser } from "./LoginProviderUser";
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js';
import { AuthError } from '../auth/AuthError';

export class AwsCognitoLoginProvider implements LoginProvider {
  config: CognitoConfig;

  static toAuthError = (error) => {
    switch (error.code) {
      case 'InvalidPasswordException':
        return AuthError.SignupInvalidPassword;
      case 'UsernameExistsException':
        return AuthError.SignupUsernameExistsAlready;
      case 'UserNotFoundException':
      case 'NotAuthorizedException':
        return AuthError.LoginFailed;
      default:
        return AuthError.SignupFailed;
    }
  }

  constructor(config: CognitoConfig) {
    this.config = config;
  }

  /**
   * Constructs a CognitoUser that is needed for login and token refresh.
   */
  private getCognitoUser(userName: string): AmazonCognitoIdentity.CognitoUser {
    const poolData: AmazonCognitoIdentity.ICognitoUserPoolData = {
      UserPoolId: this.config.userPoolId,
      ClientId: this.config.clientId
    };
    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const userData: AmazonCognitoIdentity.ICognitoUserData = {
      Username: userName,
      Pool: userPool
    };
    return new AmazonCognitoIdentity.CognitoUser(userData);
  }

  private userFromCognitoUserSession(session: AmazonCognitoIdentity.CognitoUserSession): LoginProviderUser {
    const idPayload = session.getIdToken().decodePayload();
    return <LoginProviderUser> {
      userName: idPayload['sub'],
      email: idPayload['email'],
      firstName: idPayload['given_name'],
      lastName: idPayload['family_name'],
      accessToken: session.getAccessToken().getJwtToken()
    };
  }

  async getUser(loginData: LoginData): Promise<LoginProviderUser> {
    if (!loginData || !loginData.userName || !loginData.password) {
      throw AuthError.LoginFailed;
    }
    const cognitoUser = this.getCognitoUser(loginData.userName);

    const authenticationData: AmazonCognitoIdentity.IAuthenticationDetailsData = {
      Username: loginData.userName,
      Password: loginData.password
    };
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);

    const cognitoSession = await new Promise<AmazonCognitoIdentity.CognitoUserSession>((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session: AmazonCognitoIdentity.CognitoUserSession) => {
          console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
          resolve(session);
        },
        onFailure: err => {
          console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
          reject(AwsCognitoLoginProvider.toAuthError(err));
        }
      });
    })

    return this.userFromCognitoUserSession(cognitoSession);
  }

  async refresh(accessToken: string): Promise<UserSession> {
    return null;
  }

  async logout(logoutData: LogoutData): Promise<void> {

  }
}