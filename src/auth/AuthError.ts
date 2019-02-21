export class AuthError extends Error {
  static Unauthorized: AuthError = new AuthError(403, 'Unauthorized');
  static SignupFailed: AuthError = new AuthError(9000, 'Signup failed');
  static SignupUsernameExistsAlready: AuthError = new AuthError(9001, 'User name already exists');
  static SignupInvalidPassword: AuthError = new AuthError(9002, 'Invalid password');
  static LoginFailed: AuthError = new AuthError(9003, 'Invalid user name or password');
  static RefreshTokenNotFound: AuthError = new AuthError(9005, 'Refresh token not found');
  static UserNotFound: AuthError = new AuthError(9006, 'User not found');

  statusCode?: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}