import * as AWS from 'aws-sdk';
import * as uuidv4 from 'uuid/v4';
import { AwsCognitoPublicKey } from '../AwsCognitoPublicKey';
import * as AmazonCognitoIdentity from 'amazon-cognito-identity-js';
import { AuthError } from "./AuthError";
import { AwsAuthServiceConfig } from './AwsAuthServiceConfig';
import { TokenInfo, UserGroup } from "../TokenInfo";
import { SignupData } from "../SignupData";
import { User } from "../user/User";
import { UserSession } from "../user/UserSession";
import UserMapper from "../user/UserMapper";
import UserSessionMapper from "../user/UserSessionMapper";
import { LoginData } from '../LoginData';
import { UserRepository } from '../user/UserRepository';
import { AuthService } from './AuthService';
import { AwsCognitoIdentityIdProvider } from './AwsCognitoIdentityIdProvider';

const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');

/**
 * Converts an AWS Cognito error to a SportboardError. Placed here because the AWS Cognito SDK
 * messed up the 'this' references inside the callbacks
 */
const toAuthError = (error) => {
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

export class AwsAuthService implements AuthService, AwsCognitoIdentityIdProvider {

  userRepository: UserRepository;
  config: AwsAuthServiceConfig;
  jwkPems: Map<string, any>;

  constructor(userRepository: UserRepository, config: AwsAuthServiceConfig) {
    this.userRepository = userRepository;
    this.config = config;
    this.buildJwkPems(this.config.publicCognitoKeys);
    this.getJwkPem = this.getJwkPem.bind(this);
  }

  private buildJwkPems(keys: AwsCognitoPublicKey[]) {
    this.jwkPems = new Map();
    keys.forEach(key => this.jwkPems.set(key.kid, jwkToPem(key)));
  }

  /**
   * Looks through the available JSON Web Keys to find one whose keyId matches the
   * header of a JSON Web token that is about to be verified.
   */
  private getJwkPem(header, callback) {
    callback(null, this.jwkPems.get(header.kid));
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

  private getCognitoIdentityId(user: User, userSession: AmazonCognitoIdentity.CognitoUserSession): Promise<string> {
    if (user.cognitoIdentityId) {
      return Promise.resolve(user.cognitoIdentityId);
    } else {
      return new Promise((resolve, reject) => {
        const params = {
          IdentityPoolId: this.config.identityPoolId,
          Logins: {
            [`cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}`]: userSession.getIdToken().getJwtToken()
          }
        };
        const cognitoIdentity = new AWS.CognitoIdentity({ apiVersion: '2014-06-30', region: this.config.region });
        cognitoIdentity.getId(params, function (err, response) {
          if (err) {
            reject(err)
          } else {
            resolve(response.IdentityId);
          }
        });
      });
    }
  }

  /**
   * Verifies a JSON Web token and compiles information about it in a TokenInfo
   * instance. This is information regarding it's userName, if its valid or expired etc.
   * It also puts the token in a UserGroup: Guest, User or SiteAdmin.
   */
  verifyJwt(header: string): Promise<TokenInfo> {
    let userName;
    let userGroup = UserGroup.Guest;
    let isValid = true;
    let isExpired = false;
    if (header && header.startsWith('Bearer ')) {
      let token = header.slice(7, header.length);
      jwt.verify(token, this.getJwkPem, { algorithms: ['RS256'] }, (error, decoded) => {
        if (error) {
          isValid = false;
          if (error.name == 'TokenExpiredError') {
            userName = jwt.decode(token)['username'];
            isExpired = true;
          } else {
            console.log(`JWT verification failed. Error: ${error}`);
          }
        } else {
          // JWT format is valid, but does it have the correct contents?
          if (!decoded['username']) {
            isValid = false;
          }
          userName = decoded['username'];
          if (decoded['cognito:groups'] && decoded['cognito:groups'].indexOf('site_admin') >= 0) {
            userGroup = UserGroup.SiteAdmin;
          } else {
            userGroup = UserGroup.User;
          }
        }
      });
    }
    return Promise.resolve(<TokenInfo>{ userName, isValid, isExpired, group: userGroup });
  }

  verifyAuthorizedJwt(header: string): Promise<TokenInfo> {
    return this.verifyJwt(header)
      .then(tokenInfo => {
        if (tokenInfo.group == UserGroup.Guest) {
          return Promise.reject(AuthError.Unauthorized);
        } else {
          return Promise.resolve(tokenInfo);
        }
      })
  }

  signup(signupData: SignupData): Promise<void> {
    var poolData: AmazonCognitoIdentity.ICognitoUserPoolData = {
      UserPoolId: this.config.userPoolId,
      ClientId: this.config.clientId
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    var attributeList: AmazonCognitoIdentity.CognitoUserAttribute[] = [];

    attributeList.push(
      new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'email', Value: signupData.email }),
      new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'given_name', Value: signupData.firstName }),
      new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'family_name', Value: signupData.lastName })
    );

    return new Promise((resolve, reject) => {
      userPool.signUp(signupData.email, signupData.password, attributeList, null, (err, result) => {
        if (err) {
          console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
          reject(toAuthError(err));
        } else {
          console.log('user name is ' + result.user.getUsername());
          resolve(result.userSub);
        }
      });
    })
      .then(userName => this.userRepository.put(<User>{
        userName,
        email: signupData.email,
        firstName: signupData.firstName,
        lastName: signupData.lastName
      }));
  }

  refresh(authHeader: string): Promise<UserSession> {
    return this.verifyJwt(authHeader)
      .then(tokenInfo => {
        return this.userRepository.getByUserName(tokenInfo.userName)
          .then(user => {
            if (!user) {
              return Promise.reject(AuthError.RefreshTokenNotFound);
            }
            const cognitoUser = this.getCognitoUser(user.userName);
            return new Promise((resolve, reject) => {
              const refreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: user.refreshToken });
              cognitoUser.refreshSession(refreshToken, (err, session) => {
                if (err) {
                  console.log(`AWS Cognito refresh error: ${JSON.stringify(err)}`);
                  reject(toAuthError(err));
                } else {
                  console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
                  resolve(session);
                }
              })
            })
              .then((cognitoUserSession: AmazonCognitoIdentity.CognitoUserSession) => {
                return this.getCognitoIdentityId(user, cognitoUserSession)
                  .then(cognitoIdentityId => this.userRepository.put(UserMapper.fromCognitoUserSession(cognitoUserSession, cognitoIdentityId)))
                  .then(() => Promise.resolve(UserSessionMapper.fromCognitoUserSession(cognitoUserSession)));
              });
          })
      });
  }

  login(loginData: LoginData): Promise<UserSession> {
    const cognitoUser = this.getCognitoUser(loginData.userName);

    const authenticationData: AmazonCognitoIdentity.IAuthenticationDetailsData = {
      Username: loginData.userName,
      Password: loginData.password
    };
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);

    return new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session: AmazonCognitoIdentity.CognitoUserSession) => {
          console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
          resolve(session);
        },
        onFailure: function (err) {
          console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
          reject(toAuthError(err));
        }
      });
    })
      .then((session: AmazonCognitoIdentity.CognitoUserSession) => {
        return this.getCognitoIdentityId(session.getIdToken().payload.sub, session)
          .then(cognitoIdentityId => this.userRepository.put(UserMapper.fromCognitoUserSession(session, cognitoIdentityId)))
          .then(() => Promise.resolve(UserSessionMapper.fromCognitoUserSession(session)));
      });
  }

  deleteUser(userName: string): Promise<void> {
    const idProvider = new AWS.CognitoIdentityServiceProvider({ region: this.config.region });
    const params = {
      UserPoolId: this.config.userPoolId,
      Username: userName
    }
    return idProvider.adminDeleteUser(params).promise()
      .then(() => Promise.resolve())
      .catch(error => Promise.reject(toAuthError(error)));
  }

  getIdentityIdByUser(userName: string): Promise<string> {
    return this.userRepository.getByUserName(userName)
      .then(user => {
        if (!user) {
          return Promise.reject(AuthError.UserNotFound);
        }
        return Promise.resolve(user.cognitoIdentityId);
      });
  }
}