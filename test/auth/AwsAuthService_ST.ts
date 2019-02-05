import * as AWS from 'aws-sdk';
import { AwsAuthService } from '../../src/auth/AwsAuthService';
import { InMemoryUserRepository } from './InMemoryUserRepository';
import { default as secret } from './secret';
import { SignupData } from '../../src/SignupData';
import { UserSession } from '../../lib/user/UserSession';

// @ts-ignore: No implicit any
global['fetch'] = require('node-fetch');

const setupCredentials = (userSession: UserSession): Promise<string> => {
  return new Promise((resolve, reject) => {
    AWS.config.update({
      region: 'eu-west-1',
      credentials: new AWS.CognitoIdentityCredentials({
        IdentityPoolId: 'eu-west-1:5541a34e-d5ae-4e03-8220-dd9e1cf83d95',
        Logins: {
          ['cognito-idp.eu-west-1.amazonaws.com/eu-west-1_eNRvBlO5N']: userSession.idToken
        }
      })
    });
    const credentials = <AWS.CognitoIdentityCredentials>AWS.config.credentials;
    credentials.get((error) => {
      console.log(`Credentials: ${JSON.stringify(credentials.identityId)}`);
      if (error) {
        reject(error);
      } else {
        resolve(credentials.identityId);
      }
    });
  });
}

const uploadS3File = (awsIdentity: string): Promise<void> => {
  return new Promise((resolve, reject) => {
    const s3 = new AWS.S3({
      apiVersion: '2006-03-01'
    });
    s3.putObject({
      Key: `images/${awsIdentity}/image1`,
      Bucket: 'pixerva-dev',
      Body: 'Litet test'
    }, (err, data) => {
      if (err) {
        return reject(err);
      } else {
        resolve();
      }
    });
  });
}

describe('AwsAuthService', () => {
  it('will login and get access credentials', () => {
    const userRepository = new InMemoryUserRepository();
    const sut = new AwsAuthService(userRepository, {
      region: 'eu-west-1',
      userPoolId: 'eu-west-1_eNRvBlO5N',
      clientId: '2gc8kabho4k6onquoacenl68nl',
      identityPoolId: 'eu-west-1:5541a34e-d5ae-4e03-8220-dd9e1cf83d95',
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
      .then(userSession => {
        console.log(`User session: ${JSON.stringify(userSession)}`);
        return Promise.resolve(userSession);
      })
      .then(userSession => {
        return setupCredentials(userSession)
          .then(awsIdentity => uploadS3File(awsIdentity));
      })
  });
});