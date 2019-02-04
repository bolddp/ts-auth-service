import { AwsAuthService } from '../../src/auth/AwsAuthService';
import { InMemoryUserRepository } from './InMemoryUserRepository';
import { default as secret } from './secret';
import { SignupData } from '../../src/SignupData';
import { UserSession } from '../../lib/user/UserSession';

// @ts-ignore: No implicit any
global['fetch'] = require('node-fetch');

describe('AwsAuthService', () => {
  it('will login and get access credentials', () => {
    const userRepository = new InMemoryUserRepository();
    const sut = new AwsAuthService(userRepository, {
      region: 'eu-west-1',
      userPoolId: 'eu-west-1_eNRvBlO5N',
      clientId: '2gc8kabho4k6onquoacenl68nl',
      publicCognitoKeys: secret
    });
    // sut.signup(<SignupData> {
    //   email: 'bighatsmallfeet@gmail.com',
    //   firstName: 'Daniel',
    //   lastName: 'Persson',
    //   password: 'MittTest01'
    // });
    sut.login({
      userName: 'bighatsmallfeet@gmail.com',
      password: 'MittTest01'
    })
    .then(userSession => console.log(`User session: ${JSON.stringify(userSession)}`));
  });
});