import { CognitoUserSession } from "amazon-cognito-identity-js";
import { UserSession } from "./UserSession";

export default class UserSessionMapper {
  static fromCognitoUserSession(session: CognitoUserSession) : UserSession {
    const idPayload = session.getIdToken().decodePayload();
    return <UserSession> {
      userName: idPayload['sub'],
      email: idPayload['email'],
      emailVerified: idPayload['email_verified'],
      firstName: idPayload['given_name'],
      lastName: idPayload['family_name'],
      groups: idPayload['cognito:groups'] || [],
      tokenExpiry: idPayload['exp'],
      accessToken: session.getAccessToken().getJwtToken(),
      idToken: session.getIdToken().getJwtToken()
    }
  }
}