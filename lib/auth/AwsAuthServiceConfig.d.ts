import { AwsCognitoPublicKey } from "../AwsCognitoPublicKey";
export interface AwsAuthServiceConfig {
    userPoolId: string;
    clientId: string;
    identityPoolId: string;
    region: string;
    publicCognitoKeys: AwsCognitoPublicKey[];
}
