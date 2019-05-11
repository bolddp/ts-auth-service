export declare class AuthError extends Error {
    static Unauthorized: AuthError;
    static SignupFailed: AuthError;
    static SignupUsernameExistsAlready: AuthError;
    static SignupInvalidPassword: AuthError;
    static LoginFailed: AuthError;
    static AccessTokenNotFound: AuthError;
    static RefreshTokenNotFound: AuthError;
    static UserNotFound: AuthError;
    statusCode?: number;
    constructor(statusCode: number, message: string);
}
