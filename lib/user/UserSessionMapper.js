"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class UserSessionMapper {
    static fromCognitoUserSession(session) {
        const idPayload = session.getIdToken().decodePayload();
        return {
            userName: idPayload['sub'],
            email: idPayload['email'],
            emailVerified: idPayload['email_verified'],
            firstName: idPayload['given_name'],
            lastName: idPayload['family_name'],
            groups: idPayload['cognito:groups'] || [],
            tokenExpiry: idPayload['exp'],
            accessToken: session.getAccessToken().getJwtToken(),
            idToken: session.getIdToken().getJwtToken()
        };
    }
}
exports.default = UserSessionMapper;
