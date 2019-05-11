import { AwsCognitoPublicKey } from '../AwsCognitoPublicKey';
export interface CognitoConfig {
    userPoolId: string;
    clientId: string;
    region: string;
    publicCognitoKeys: AwsCognitoPublicKey[];
    identityPoolId: string;
}
export interface FacebookConfig {
    appId: string;
    appSecret: string;
    passwordSalt: string;
}
export interface AwsAuthServiceConfig {
    cognito: CognitoConfig;
    facebook?: FacebookConfig;
}
