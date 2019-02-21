import { AwsCognitoPublicKey } from '../AwsCognitoPublicKey';
export interface AwsAuthServiceConfig {
    userPoolId: string;
    clientId: string;
    region: string;
    publicCognitoKeys: AwsCognitoPublicKey[];
    identityPoolId: string;
}
