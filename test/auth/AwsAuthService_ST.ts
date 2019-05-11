import { expect } from 'chai';
import * as fetch from 'node-fetch';
import { default as secret } from './secret';
import { AwsAuthService } from '../../src/auth/AwsAuthService';
import { InMemoryUserRepository } from './InMemoryUserRepository';
import { LoginData, LoginProviderEnum } from '../../src/LoginData';

global['fetch'] = fetch;

describe('AwsAuthService', () => {

  it('will login through Facebook', async () => {
    const userRepository = new InMemoryUserRepository();
    const sut = new AwsAuthService(userRepository, {
      cognito: {
        userPoolId: secret.userPoolId,
        clientId: secret.clientId,
        region: 'eu-west-1',
        publicCognitoKeys: secret.keys,
        identityPoolId: secret.identityPoolId
      },
      facebook: {
        appId: secret.facebook.appId,
        appSecret: secret.facebook.appSecret,
        passwordSalt: secret.facebook.passwordSalt
      }
    });
    const userSession = await sut.login(<LoginData> {
      loginProvider: LoginProviderEnum.Facebook,
      accessToken: secret.facebook.accessToken
    });

    console.log(`User session: ${JSON.stringify(userSession, null, 2)}`);

    expect(userSession.userName).to.equal('37f8fe94-9008-4524-a14e-0324fc7e6f4f');
    expect(userRepository.user.cognitoIdentityId).to.not.be.undefined;
    console.log(`Cognito identity id: ${userRepository.user.cognitoIdentityId}`);
  });

  // it('will login and get identity id', () => {
  //   const userRepository = new InMemoryUserRepository();
  //   const sut = new AwsAuthService(userRepository, {
  //     cognito: {
  //       userPoolId: secret.userPoolId,
  //       clientId: secret.clientId,
  //       region: 'eu-west-1',
  //       publicCognitoKeys: secret.keys,
  //       identityPoolId: secret.identityPoolId
  //     }
  //   });
  //   return sut.login(<LoginData> {
  //     userName: secret.userName,
  //     password: secret.password
  //   })
  //   .then(userSession => {
  //     expect(userSession.userName).to.equal('37f8fe94-9008-4524-a14e-0324fc7e6f4f');
  //     expect(userRepository.user.cognitoIdentityId).to.not.be.undefined;
  //     console.log(`Cognito identity id: ${userRepository.user.cognitoIdentityId}`);
  //   });
  // });
});