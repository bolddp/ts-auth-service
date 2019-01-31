export declare class AuthError extends Error {
    static SignupFailed: AuthError;
    static SignupUsernameExistsAlready: AuthError;
    static SignupInvalidPassword: AuthError;
    static LoginFailed: AuthError;
    static RefreshTokenNotFound: AuthError;
    statusCode?: number;
    constructor(statusCode: number, message: string);
}