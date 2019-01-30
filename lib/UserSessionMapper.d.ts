import { CognitoUserSession } from "amazon-cognito-identity-js";
import { UserSession } from "./UserSession";
export default class UserSessionMapper {
    static fromCognitoUserSession(session: CognitoUserSession): UserSession;
}
