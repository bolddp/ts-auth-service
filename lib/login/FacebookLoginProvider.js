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
const crypto = require("crypto");
const LoginData_1 = require("../LoginData");
const AuthError_1 = require("../auth/AuthError");
class FacebookLoginProvider {
    constructor(config) {
        this.config = config;
    }
    createPermanentPassword(salt, userName) {
        const hash = crypto.createHash('sha1').update(`${salt}_${userName}`).digest('hex');
        return `PWD_${hash}`;
    }
    getUser(loginData) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!loginData.accessToken) {
                throw AuthError_1.AuthError.AccessTokenNotFound;
            }
            const token = loginData.accessToken;
            const longLivedTokenInfo = yield fetch(`https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=${this.config.appId}&client_secret=${this.config.appSecret}&fb_exchange_token=${token}`)
                .then(response => response.json());
            const userInfo = yield fetch(`https://graph.facebook.com/me?access_token=${token}&fields=id,email,first_name,last_name`)
                .then(response => response.json());
            const userName = `${LoginData_1.LoginProviderEnum.Facebook}_${userInfo.id}`;
            return {
                userName,
                permanentPassword: this.createPermanentPassword(this.config.passwordSalt, userName),
                loginProvider: LoginData_1.LoginProviderEnum.Facebook,
                email: decodeURI(userInfo.email),
                firstName: decodeURI(userInfo.first_name),
                lastName: decodeURI(userInfo.last_name),
                accessToken: longLivedTokenInfo.access_token,
                accessTokenExpiry: new Date().getTime() + (longLivedTokenInfo.expires_in * 1000)
            };
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
exports.FacebookLoginProvider = FacebookLoginProvider;
