import { AwsAuthServiceConfig } from "./AwsAuthServiceConfig";
import { TokenInfo } from "../TokenInfo";
import { SignupData } from "../SignupData";
import { UserSession } from "../user/UserSession";
import { LoginData } from '../LoginData';
import { UserRepository } from '../user/UserRepository';
export declare class AwsAuthService implements AwsAuthService {
    userRepository: UserRepository;
    config: AwsAuthServiceConfig;
    jwkPems: Map<string, any>;
    constructor(userRepository: UserRepository, config: AwsAuthServiceConfig);
    private buildJwkPems;
    /**
     * Looks through the available JSON Web Keys to find one whose keyId matches the
     * header of a JSON Web token that is about to be verified.
     */
    private getJwkPem;
    /**
     * Constructs a CognitoUser that is needed for login and token refresh.
     */
    private getCognitoUser;
    /**
     * Verifies a JSON Web token and compiles information about it in a TokenInfo
     * instance. This is information regarding it's userName, if its valid or expired etc.
     * It also puts the token in a UserGroup: Guest, User or SiteAdmin.
     */
    verifyJwt(header: string): Promise<TokenInfo>;
    signup(signupData: SignupData): Promise<void>;
    refresh(authHeader: string): Promise<UserSession>;
    login(loginData: LoginData): Promise<UserSession>;
    deleteUser(userName: string): Promise<void>;
}
