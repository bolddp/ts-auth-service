"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const AWS = require("aws-sdk");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const AuthError_1 = require("./AuthError");
const TokenInfo_1 = require("../TokenInfo");
const UserMapper_1 = require("../user/UserMapper");
const UserSessionMapper_1 = require("../user/UserSessionMapper");
const LoginData_1 = require("../LoginData");
const FacebookLoginProvider_1 = require("../login/FacebookLoginProvider");
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
/**
 * Converts an AWS Cognito error to a SportboardError. Placed here because the AWS Cognito SDK
 * messed up the 'this' references inside the callbacks
 */
const toAuthError = (error) => {
    switch (error.code) {
        case 'InvalidPasswordException':
            return AuthError_1.AuthError.SignupInvalidPassword;
        case 'UsernameExistsException':
            return AuthError_1.AuthError.SignupUsernameExistsAlready;
        case 'UserNotFoundException':
        case 'NotAuthorizedException':
            return AuthError_1.AuthError.LoginFailed;
        default:
            return AuthError_1.AuthError.SignupFailed;
    }
};
class AwsAuthService {
    constructor(userRepository, config) {
        this.userRepository = userRepository;
        this.config = config;
        this.buildJwkPems(this.config.cognito.publicCognitoKeys);
        this.getJwkPem = this.getJwkPem.bind(this);
        this.identityServiceProvider = new AWS.CognitoIdentityServiceProvider({ region: this.config.cognito.region });
        this.loginProviders = {
            [LoginData_1.LoginProviderEnum.Facebook]: new FacebookLoginProvider_1.FacebookLoginProvider(config.facebook)
        };
    }
    buildJwkPems(keys) {
        this.jwkPems = new Map();
        keys.forEach(key => this.jwkPems.set(key.kid, jwkToPem(key)));
    }
    /**
     * Looks through the available JSON Web Keys to find one whose keyId matches the
     * header of a JSON Web token that is about to be verified.
     */
    getJwkPem(header, callback) {
        callback(null, this.jwkPems.get(header.kid));
    }
    /**
     * Constructs a CognitoUser that is needed for login and token refresh.
     */
    getCognitoUser(userName) {
        const poolData = {
            UserPoolId: this.config.cognito.userPoolId,
            ClientId: this.config.cognito.clientId
        };
        const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        const userData = {
            Username: userName,
            Pool: userPool
        };
        return new AmazonCognitoIdentity.CognitoUser(userData);
    }
    getCognitoIdentityId(userSession) {
        return new Promise((resolve, reject) => {
            const params = {
                IdentityPoolId: this.config.cognito.identityPoolId,
                Logins: {
                    [`cognito-idp.${this.config.cognito.region}.amazonaws.com/${this.config.cognito.userPoolId}`]: userSession.getIdToken().getJwtToken()
                }
            };
            const cognitoIdentity = new AWS.CognitoIdentity({ apiVersion: '2014-06-30', region: this.config.cognito.region });
            cognitoIdentity.getId(params, function (err, response) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(response.IdentityId);
                }
            });
        });
    }
    checkUserExists(user) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.identityServiceProvider.adminGetUser({
                UserPoolId: this.config.cognito.userPoolId,
                Username: user.email
            }).promise().then(response => {
                return true;
            }).catch(error => {
                if (error.code == 'UserNotFoundException') {
                    return false;
                }
                throw error;
            });
        });
    }
    createUser(user) {
        return __awaiter(this, void 0, void 0, function* () {
            // First create the user and capture its new user name
            const userName = yield this.identityServiceProvider.adminCreateUser({
                UserPoolId: this.config.cognito.userPoolId,
                Username: user.email,
                DesiredDeliveryMediums: ['EMAIL'],
                ForceAliasCreation: false,
                MessageAction: 'SUPPRESS',
                TemporaryPassword: '!ItIsTemp01',
                UserAttributes: [
                    { Name: 'email', Value: user.email },
                    { Name: 'given_name', Value: user.firstName },
                    { Name: 'family_name', Value: user.lastName }
                ]
            }).promise().then(rsp => {
                return Promise.resolve(rsp.User.Username);
            });
            // Then set the corresponding permanent password
            yield this.identityServiceProvider.adminSetUserPassword({
                UserPoolId: this.config.cognito.userPoolId,
                Username: userName,
                Password: user.permanentPassword,
                Permanent: true
            }).promise();
        });
    }
    /**
     * Verifies a JSON Web token and compiles information about it in a TokenInfo
     * instance. This is information regarding it's userName, if its valid or expired etc.
     * It also puts the token in a UserGroup: Guest, User or SiteAdmin.
     */
    verifyJwt(header) {
        let userName;
        let userGroup = TokenInfo_1.UserGroup.Guest;
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
                    }
                    else {
                        console.log(`JWT verification failed. Error: ${error}`);
                    }
                }
                else {
                    // JWT format is valid, but does it have the correct contents?
                    if (!decoded['username']) {
                        isValid = false;
                    }
                    userName = decoded['username'];
                    if (decoded['cognito:groups'] && decoded['cognito:groups'].indexOf('site_admin') >= 0) {
                        userGroup = TokenInfo_1.UserGroup.SiteAdmin;
                    }
                    else {
                        userGroup = TokenInfo_1.UserGroup.User;
                    }
                }
            });
        }
        return Promise.resolve({ userName, isValid, isExpired, group: userGroup });
    }
    verifyAuthorizedJwt(header) {
        return this.verifyJwt(header)
            .then(tokenInfo => {
            if (tokenInfo.group == TokenInfo_1.UserGroup.Guest) {
                return Promise.reject(AuthError_1.AuthError.Unauthorized);
            }
            else {
                return Promise.resolve(tokenInfo);
            }
        });
    }
    signup(signupData) {
        var poolData = {
            UserPoolId: this.config.cognito.userPoolId,
            ClientId: this.config.cognito.clientId
        };
        var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        var attributeList = [];
        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'email', Value: signupData.email }), new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'given_name', Value: signupData.firstName }), new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'family_name', Value: signupData.lastName }));
        return new Promise((resolve, reject) => {
            userPool.signUp(signupData.email, signupData.password, attributeList, null, (err, result) => {
                if (err) {
                    console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
                    reject(toAuthError(err));
                }
                else {
                    console.log('user name is ' + result.user.getUsername());
                    resolve(result.userSub);
                }
            });
        })
            .then(userName => this.userRepository.put({
            userName,
            email: signupData.email,
            firstName: signupData.firstName,
            lastName: signupData.lastName
        }));
    }
    refresh(authHeader) {
        return __awaiter(this, void 0, void 0, function* () {
            const tokenInfo = yield this.verifyJwt(authHeader);
            const existingUser = yield this.userRepository.getByUserName(tokenInfo.userName);
            if (!existingUser) {
                throw AuthError_1.AuthError.RefreshTokenNotFound;
            }
            const cognitoUser = this.getCognitoUser(existingUser.userName);
            const cognitoSession = yield new Promise((resolve, reject) => {
                const refreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: existingUser.refreshToken });
                cognitoUser.refreshSession(refreshToken, (err, session) => {
                    if (err) {
                        console.log(`AWS Cognito refresh error: ${JSON.stringify(err)}`);
                        reject(toAuthError(err));
                    }
                    else {
                        console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
                        resolve(session);
                    }
                });
            });
            const refreshUser = UserMapper_1.default.fromCognitoUserSession(cognitoSession, existingUser.cognitoIdentityId);
            this.userRepository.put(refreshUser);
            return UserSessionMapper_1.default.fromCognitoUserSession(cognitoSession);
        });
    }
    login(loginData) {
        return __awaiter(this, void 0, void 0, function* () {
            let userNameToUse = loginData.userName;
            let passwordToUse = loginData.password;
            if (loginData.loginProvider != LoginData_1.LoginProviderEnum.AwsCognito) {
                const loginProvider = this.loginProviders[loginData.loginProvider];
                if (!loginProvider) {
                    throw AuthError_1.AuthError.LoginFailed;
                }
                const loginProviderUser = yield loginProvider.getUser(loginData);
                const userExists = yield this.checkUserExists(loginProviderUser);
                if (!userExists) {
                    yield this.createUser(loginProviderUser);
                }
                userNameToUse = loginProviderUser.email;
                passwordToUse = loginProviderUser.permanentPassword;
            }
            const cognitoUser = this.getCognitoUser(userNameToUse);
            const authenticationData = {
                Username: userNameToUse,
                Password: passwordToUse
            };
            const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
            const cognitoSession = yield new Promise((resolve, reject) => {
                cognitoUser.authenticateUser(authenticationDetails, {
                    onSuccess: (session) => {
                        console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
                        resolve(session);
                    },
                    onFailure: function (err) {
                        console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
                        reject(toAuthError(err));
                    }
                });
            });
            const loginUser = UserMapper_1.default.fromCognitoUserSession(cognitoSession);
            const existingUser = yield this.userRepository.getByUserName(loginUser.userName);
            if (!existingUser) {
                loginUser.cognitoIdentityId = yield this.getCognitoIdentityId(cognitoSession);
            }
            // Overwrite user each time since data may have changed (e.g. new name on Facebook)
            yield this.userRepository.put(loginUser);
            return UserSessionMapper_1.default.fromCognitoUserSession(cognitoSession);
        });
    }
    logout(authHeader) {
        return __awaiter(this, void 0, void 0, function* () {
            const tokenInfo = yield this.verifyJwt(authHeader);
            const existingUser = yield this.userRepository.getByUserName(tokenInfo.userName);
            if (!existingUser) {
                throw AuthError_1.AuthError.RefreshTokenNotFound;
            }
            else {
                existingUser.refreshToken = undefined;
                yield this.userRepository.put(existingUser);
            }
            const cognitoUser = this.getCognitoUser(existingUser.userName);
            cognitoUser.signOut();
        });
    }
    deleteUser(userName) {
        const idProvider = new AWS.CognitoIdentityServiceProvider({ region: this.config.cognito.region });
        const params = {
            UserPoolId: this.config.cognito.userPoolId,
            Username: userName
        };
        return idProvider.adminDeleteUser(params).promise()
            .then(() => Promise.resolve())
            .catch(error => Promise.reject(toAuthError(error)));
    }
    getIdentityIdByUser(userName) {
        return this.userRepository.getByUserName(userName)
            .then(user => {
            if (!user) {
                return Promise.reject(AuthError_1.AuthError.UserNotFound);
            }
            return Promise.resolve(user.cognitoIdentityId);
        });
    }
}
exports.AwsAuthService = AwsAuthService;
