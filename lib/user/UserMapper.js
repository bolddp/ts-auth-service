"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class UserMapper {
    static fromCognitoUserSession(session) {
        const idPayload = session.getIdToken().decodePayload();
        return {
            userName: idPayload['sub'],
            email: idPayload['email'],
            firstName: idPayload['given_name'],
            lastName: idPayload['family_name'],
            refreshToken: session.getRefreshToken().getToken()
        };
    }
}
exports.default = UserMapper;
