import { CognitoUserSession } from 'amazon-cognito-identity-js';
import { User } from './User';

export default class UserMapper {
  static fromCognitoUserSession(session: CognitoUserSession, cognitoIdentityId: string) {
    const idPayload = session.getIdToken().decodePayload();
    return <User> {
      userName: idPayload['sub'],
      email: idPayload['email'],
      firstName: idPayload['given_name'],
      lastName: idPayload['family_name'],
      refreshToken: session.getRefreshToken().getToken(),
      cognitoIdentityId
    };
  }
}