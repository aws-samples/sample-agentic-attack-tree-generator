import assert from 'node:assert/strict';
import test from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { IdentityStack } from '../src/identity-stack.js';

function template(): Template {
  const app = new App();
  const stack = new IdentityStack(app, 'TestIdentity', {
    env: { account: '123456789012', region: 'eu-west-2' },
    callbackUrls: ['https://threatforest.example/auth/callback'],
    logoutUrls: ['https://threatforest.example/auth/logout'],
    domainPrefix: 'threatforest-test-identity',
  });
  return Template.fromStack(stack);
}

test('user pool permits only administrator-created users', () => {
  const value = template();
  value.hasResourceProperties('AWS::Cognito::UserPool', {
    AdminCreateUserConfig: {
      AllowAdminCreateUserOnly: true,
      InviteMessageTemplate: Match.objectLike({
        EmailSubject: 'Your ThreatForest invitation',
      }),
    },
    AutoVerifiedAttributes: ['email'],
    UsernameAttributes: ['email'],
    UsernameConfiguration: { CaseSensitive: false },
    DeletionProtection: 'ACTIVE',
    Policies: {
      PasswordPolicy: Match.objectLike({
        MinimumLength: 14,
        RequireLowercase: true,
        RequireUppercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
      }),
    },
  });
});

test('SPA client is public and authorization-code only', () => {
  const value = template();
  value.hasResourceProperties('AWS::Cognito::UserPoolClient', {
    GenerateSecret: false,
    AllowedOAuthFlows: ['code'],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: Match.arrayWith(['openid', 'email', 'profile']),
    CallbackURLs: ['https://threatforest.example/auth/callback'],
    LogoutURLs: ['https://threatforest.example/auth/logout'],
    PreventUserExistenceErrors: 'ENABLED',
    SupportedIdentityProviders: ['COGNITO'],
  });

  const clients = value.findResources('AWS::Cognito::UserPoolClient');
  const client = Object.values(clients)[0] as { Properties: Record<string, unknown> };
  assert.deepEqual(client.Properties.AllowedOAuthFlows, ['code']);
  assert.equal(client.Properties.GenerateSecret, false);
});

test('new managed login is configured with Cognito-provided branding', () => {
  const value = template();
  value.hasResourceProperties('AWS::Cognito::UserPoolDomain', {
    Domain: 'threatforest-test-identity',
    ManagedLoginVersion: 2,
  });
  value.hasResourceProperties('AWS::Cognito::ManagedLoginBranding', {
    ClientId: Match.anyValue(),
    UserPoolId: Match.anyValue(),
    UseCognitoProvidedValues: true,
  });
});

test('identity stack rejects insecure non-local callback URLs', () => {
  const app = new App();
  assert.throws(
    () =>
      new IdentityStack(app, 'InvalidIdentity', {
        env: { account: '123456789012', region: 'eu-west-2' },
        callbackUrls: ['http://example.com/auth/callback'],
        logoutUrls: ['https://example.com/auth/logout'],
      }),
    /callbackUrls must use HTTPS/,
  );
});
