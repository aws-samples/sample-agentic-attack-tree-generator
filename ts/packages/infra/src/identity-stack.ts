import {
  Duration,
  RemovalPolicy,
  Stack,
  Token,
  type StackProps,
  aws_cognito as cognito,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';

export interface IdentityStackProps extends StackProps {
  readonly callbackUrls: string[];
  readonly logoutUrls: string[];
  readonly domainPrefix?: string;
}

function validateRedirectUrls(name: string, urls: string[]): void {
  if (urls.length === 0) {
    throw new Error(`${name} must contain at least one URL`);
  }

  for (const url of urls) {
    if (
      !Token.isUnresolved(url) &&
      !url.startsWith('https://') &&
      !url.startsWith('http://localhost')
    ) {
      throw new Error(`${name} must use HTTPS, except for localhost development URLs: ${url}`);
    }
  }
}

export class IdentityStack extends Stack {
  readonly userPool: cognito.UserPool;
  readonly userPoolClient: cognito.UserPoolClient;
  readonly userPoolDomain: cognito.UserPoolDomain;
  readonly issuerUrl: string;
  readonly managedLoginBaseUrl: string;
  readonly authorizationEndpoint: string;
  readonly logoutEndpoint: string;
  readonly pkceRequired = true;

  constructor(scope: Construct, id: string, props: IdentityStackProps) {
    super(scope, id, props);

    validateRedirectUrls('callbackUrls', props.callbackUrls);
    validateRedirectUrls('logoutUrls', props.logoutUrls);

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `${DEPLOYMENT.namePrefix}-users`,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      signInCaseSensitive: false,
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      userInvitation: {
        emailSubject: 'Your ThreatForest invitation',
        emailBody:
          'Your ThreatForest username is {username} and temporary password is {####}.',
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        otp: true,
        sms: false,
      },
      passwordPolicy: {
        minLength: 14,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3),
      },
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.userPoolClient = this.userPool.addClient('SpaClient', {
      userPoolClientName: `${DEPLOYMENT.namePrefix}-spa`,
      generateSecret: false,
      authFlows: {
        userSrp: true,
      },
      preventUserExistenceErrors: true,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false,
          clientCredentials: false,
        },
        callbackUrls: props.callbackUrls,
        logoutUrls: props.logoutUrls,
        defaultRedirectUri: props.callbackUrls[0],
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
      },
      authSessionValidity: Duration.minutes(5),
      accessTokenValidity: Duration.minutes(60),
      idTokenValidity: Duration.minutes(60),
      refreshTokenValidity: Duration.days(30),
      refreshTokenRotationGracePeriod: Duration.seconds(30),
      enableTokenRevocation: true,
    });

    this.userPoolDomain = this.userPool.addDomain('ManagedLoginDomain', {
      cognitoDomain: {
        domainPrefix: props.domainPrefix ?? `${DEPLOYMENT.namePrefix}-${this.account}`,
      },
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
    });

    const branding = new cognito.CfnManagedLoginBranding(this, 'ManagedLoginBranding', {
      userPoolId: this.userPool.userPoolId,
      clientId: this.userPoolClient.userPoolClientId,
      useCognitoProvidedValues: true,
    });
    branding.addResourceDependency(
      this.userPoolDomain.node.defaultChild as cognito.CfnUserPoolDomain,
    );

    this.issuerUrl = `https://cognito-idp.${this.region}.${this.urlSuffix}/${this.userPool.userPoolId}`;
    this.managedLoginBaseUrl = this.userPoolDomain.baseUrl();
    this.authorizationEndpoint = `${this.managedLoginBaseUrl}/oauth2/authorize`;
    this.logoutEndpoint = `${this.managedLoginBaseUrl}/logout`;
  }
}
