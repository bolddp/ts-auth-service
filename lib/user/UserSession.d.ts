export interface UserSession {
    userName: string;
    email: string;
    emailVerified: boolean;
    firstName: string;
    lastName: string;
    groups: string[];
    tokenExpiry: number;
    accessToken: string;
}
