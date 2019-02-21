import { expect } from 'chai';
import * as fetch from 'node-fetch';
import { default as secret } from './secret';
import { AwsAuthService } from '../../src/auth/AwsAuthService';
import { InMemoryUserRepository } from './InMemoryUserRepository';
import { LoginData } from '../../src/LoginData';

global['fetch'] = fetch;

describe('AwsAuthService', () => {
  it('will login and get identity id', () => {
    const userRepository = new InMemoryUserRepository();
    const sut = new AwsAuthService(userRepository, {
      userPoolId: secret.userPoolId,
      clientId: secret.clientId,
      region: 'eu-west-1',
      publicCognitoKeys: secret.keys,
      identityPoolId: secret.identityPoolId
    });
    return sut.login(<LoginData> {
      userName: secret.userName,
      password: secret.password
    })
    .then(userSession => {
      expect(userSession.userName).to.equal('37f8fe94-9008-4524-a14e-0324fc7e6f4f');
      expect(userRepository.user.cognitoIdentityId).to.not.be.undefined;
      console.log(`Cognito identity id: ${userRepository.user.cognitoIdentityId}`);
    });
  });
});