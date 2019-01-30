"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const AWS = require("aws-sdk");
const uuidv4 = require("uuid/v4");
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const AuthError_1 = require("./AuthError");
const TokenInfo_1 = require("./TokenInfo");
const UserMapper_1 = require("./user/UserMapper");
const UserSessionMapper_1 = require("./user/UserSessionMapper");
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
// import * as AWS from 'aws-sdk';
// import Constants from "../../utils/Constants";
// import DI from "../../DI";
// import { Request } from "express";
// import { ClubRepository, ClubIncludes } from "../../repositories/ClubRepository";
// import { SportboardError } from "../../utils/SportBoardError";
// import { SignupData } from "../../domain/user/SignupData";
// import { LoginData } from "../../domain/user/LoginData";
// import { UserSession } from "../../domain/user/UserSession";
// import UserSessionMapper from "../../mappers/UserSessionMapper";
// import { UserRepository } from '../../repositories/UserRepository';
// import UserMapper from "../../mappers/UserMapper";
// import { CognitoUserSession } from 'amazon-cognito-identity-js';
// import { default as secret } from './secret';
// import { Club } from "../../domain/Club";
// import { User } from "../../domain/user/User";
// import * as uuidv4 from 'uuid/v4';
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
class AuthService {
    constructor(userRepository, config) {
        this.userRepository = userRepository;
        this.config = config;
        this.buildJwkPems(this.config.publicCognitoKeys);
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
    signup(signupData) {
        var poolData = {
            UserPoolId: this.config.userPoolId,
            ClientId: this.config.clientId
        };
        var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        var attributeList = [];
        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'email', Value: signupData.email }), new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'preferred_username', Value: uuidv4() }), new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'given_name', Value: signupData.firstName }), new AmazonCognitoIdentity.CognitoUserAttribute({ Name: 'family_name', Value: signupData.lastName }));
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
        return this.verifyJwt(authHeader)
            .then(tokenInfo => {
            return this.userRepository.getByUserName(tokenInfo.userName)
                .then(user => {
                if (!user) {
                    return Promise.reject(AuthError_1.AuthError.RefreshTokenNotFound);
                }
                const cognitoUser = this.getCognitoUser(user.userName);
                return new Promise((resolve, reject) => {
                    const refreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: user.refreshToken });
                    cognitoUser.refreshSession(refreshToken, (err, session) => {
                        if (err) {
                            console.log(`AWS Cognito refresh error: ${JSON.stringify(err)}`);
                            reject(toAuthError(err));
                        }
                        console.log(`Authentication success result: ${JSON.stringify(session)}`);
                        resolve(session);
                    });
                })
                    .then((cognitoUserSession) => {
                    return this.userRepository.put(UserMapper_1.default.fromCognitoUserSession(cognitoUserSession))
                        .then(() => Promise.resolve(UserSessionMapper_1.default.fromCognitoUserSession(cognitoUserSession)));
                });
            });
        });
    }
    login(loginData) {
        const cognitoUser = this.getCognitoUser(loginData.userName);
        const authenticationData = {
            Username: loginData.userName,
            Password: loginData.password
        };
        const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
        return new Promise((resolve, reject) => {
            cognitoUser.authenticateUser(authenticationDetails, {
                onSuccess: (session) => {
                    console.log(`Authentication success result: ${JSON.stringify(session)}`);
                    resolve(session);
                },
                onFailure: function (err) {
                    console.log(`AWS Cognito error: ${JSON.stringify(err)}`);
                    reject(toAuthError(err));
                }
            });
        })
            .then((cognitoUserSession) => {
            return this.userRepository.put(UserMapper_1.default.fromCognitoUserSession(cognitoUserSession))
                .then(() => Promise.resolve(UserSessionMapper_1.default.fromCognitoUserSession(cognitoUserSession)));
        });
    }
    deleteUser(userName) {
        const idProvider = new AWS.CognitoIdentityServiceProvider({ region: this.config.region });
        const params = {
            UserPoolId: this.config.userPoolId,
            Username: userName
        };
        return idProvider.adminDeleteUser(params).promise()
            .then(() => Promise.resolve())
            .catch(error => Promise.reject(toAuthError(error)));
    }
}
exports.AuthService = AuthService;
