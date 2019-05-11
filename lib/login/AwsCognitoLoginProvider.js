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
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const AuthError_1 = require("../auth/AuthError");
class AwsCognitoLoginProvider {
    constructor(config) {
        this.config = config;
    }
    /**
     * Constructs a CognitoUser that is needed for login and token refresh.
     */
    getCognitoUser(userName) {
        const poolData = {
            UserPoolId: this.config.userPoolId,
            ClientId: this.config.clientId
        };
        const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        const userData = {
            Username: userName,
            Pool: userPool
        };
        return new AmazonCognitoIdentity.CognitoUser(userData);
    }
    userFromCognitoUserSession(session) {
        const idPayload = session.getIdToken().decodePayload();
        return {
            userName: idPayload['sub'],
            email: idPayload['email'],
            firstName: idPayload['given_name'],
            lastName: idPayload['family_name'],
            accessToken: session.getAccessToken().getJwtToken()
        };
    }
    getUser(loginData) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!loginData || !loginData.userName || !loginData.password) {
                throw AuthError_1.AuthError.LoginFailed;
            }
            const cognitoUser = this.getCognitoUser(loginData.userName);
            const authenticationData = {
                Username: loginData.userName,
                Password: loginData.password
            };
            const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
            const cognitoSession = yield new Promise((resolve, reject) => {
                cognitoUser.authenticateUser(authenticationDetails, {
                    onSuccess: (session) => {
                        console.log(`Authentication succeeded (user: ${session.getIdToken().payload.sub})`);
                        resolve(session);
                    },
                    onFailure: err => {
                        console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
                        reject(AwsCognitoLoginProvider.toAuthError(err));
                    }
                });
            });
            return this.userFromCognitoUserSession(cognitoSession);
        });
    }
    refresh(accessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            return null;
        });
    }
    logout(logoutData) {
        return __awaiter(this, void 0, void 0, function* () {
        });
    }
}
AwsCognitoLoginProvider.toAuthError = (error) => {
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
exports.AwsCognitoLoginProvider = AwsCognitoLoginProvider;
