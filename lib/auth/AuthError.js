"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class AuthError extends Error {
    constructor(statusCode, message) {
        super(message);
        this.statusCode = statusCode;
    }
}
AuthError.Unauthorized = new AuthError(403, 'Unauthorized');
AuthError.SignupFailed = new AuthError(9000, 'Signup failed');
AuthError.SignupUsernameExistsAlready = new AuthError(9001, 'User name already exists');
AuthError.SignupInvalidPassword = new AuthError(9002, 'Invalid password');
AuthError.LoginFailed = new AuthError(9003, 'Invalid user name or password');
// static AuthTokenInvalid: AuthError = new AuthError(9004, 'Authorization token invalid');
AuthError.RefreshTokenNotFound = new AuthError(9005, 'Refresh token not found');
exports.AuthError = AuthError;
