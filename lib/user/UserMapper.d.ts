import { CognitoUserSession } from 'amazon-cognito-identity-js';
import { User } from './User';
export default class UserMapper {
    static fromCognitoUserSession(session: CognitoUserSession, cognitoIdentityId?: string): User;
}
