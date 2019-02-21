export interface AwsCognitoIdentityIdProvider {
  getIdentityIdByUser(userName: string): Promise<string>;
}