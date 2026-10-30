import assert from 'node:assert/strict';
import test from 'node:test';
import * as crypto from 'node:crypto';
import { runInNewContext } from 'node:vm';
import {
  App,
  CfnResource,
  Stack,
  aws_kms as kms,
  aws_logs as logs,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { EdgeStack } from '../src/edge-stack.js';

function template(): Template {
  const app = new App();
  const imports = new Stack(app, 'Imports', {
    env: { account: '123456789012', region: 'eu-west-2' },
  });
  new CfnResource(imports, 'TemplateFixture', { type: 'Custom::TemplateFixture' });
  const webBucket = s3.Bucket.fromBucketName(
    imports,
    'ImportedWebBucket',
    'threatforest-test-web-fixture',
  );
  const stack = new EdgeStack(app, 'TestEdge', {
    env: { account: '123456789012', region: 'eu-west-2' },
    webBucket,
    webAclArn:
      'arn:aws:wafv2:us-east-1:123456789012:global/webacl/threatforest-test-edge/example',
    authentication: {
      managedLoginBaseUrl:
        'https://threatforest-test.auth.eu-west-2.amazoncognito.com',
      userPoolClientId: 'exampleclientid',
      callbackUrl: 'https://threatforest.example/auth/callback',
      logoutUrl: 'https://threatforest.example/auth/logout',
    },
    apiOrigin: {
      domainName: 'api-id.execute-api.eu-west-2.amazonaws.com',
      customHeaders: { 'X-ThreatForest-Origin': 'test-origin-secret' },
    },
    webSocketOrigin: {
      domainName: 'ws-id.execute-api.eu-west-2.amazonaws.com',
      originPath: '/production',
      customHeaders: { 'X-ThreatForest-Origin': 'test-origin-secret' },
    },
    additionalConnectSources: [
      'https://threatforest-artifacts.s3.eu-west-2.amazonaws.com',
    ],
  });
  return Template.fromStack(stack);
}

test('distribution uses OAC, WAF, HTTPS, and authenticated route rewriting', () => {
  const value = template();
  value.resourceCountIs('AWS::CloudFront::OriginAccessControl', 1);
  value.hasResourceProperties('AWS::CloudFront::OriginAccessControl', {
    OriginAccessControlConfig: {
      OriginAccessControlOriginType: 's3',
      SigningBehavior: 'always',
      SigningProtocol: 'sigv4',
    },
  });
  value.hasResourceProperties('AWS::CloudFront::Distribution', {
    DistributionConfig: Match.objectLike({
      WebACLId:
        'arn:aws:wafv2:us-east-1:123456789012:global/webacl/threatforest-test-edge/example',
      DefaultRootObject: 'index.html',
      HttpVersion: 'http2and3',
      IPV6Enabled: true,
      Origins: Match.arrayWith([
        Match.objectLike({
          OriginAccessControlId: Match.anyValue(),
          S3OriginConfig: { OriginAccessIdentity: '' },
        }),
      ]),
      DefaultCacheBehavior: Match.objectLike({
        ViewerProtocolPolicy: 'redirect-to-https',
        FunctionAssociations: [
          {
            EventType: 'viewer-request',
            FunctionARN: Match.anyValue(),
          },
        ],
      }),
      CacheBehaviors: Match.arrayWith([
        Match.objectLike({
          PathPattern: 'api/*',
          ViewerProtocolPolicy: 'redirect-to-https',
        }),
        Match.objectLike({
          PathPattern: 'ws*',
          ViewerProtocolPolicy: 'redirect-to-https',
        }),
      ]),
    }),
  });

  const distribution = Object.values(value.findResources('AWS::CloudFront::Distribution'))[0] as {
    Properties: { DistributionConfig: Record<string, unknown> };
  };
  assert.equal(distribution.Properties.DistributionConfig.CustomErrorResponses, undefined);
});

test('auth gate initiates PKCE and only rewrites approved SPA navigation', () => {
  const value = template();
  const functions = value.findResources('AWS::CloudFront::Function');
  const authFunction = Object.values(functions)[0] as {
    Properties: { FunctionCode: string; FunctionConfig: { Runtime: string } };
  };
  assert.equal(authFunction.Properties.FunctionConfig.Runtime, 'cloudfront-js-2.0');
  assert.match(
    authFunction.Properties.FunctionCode,
    /const crypto = require\('crypto'\);/,
  );
  assert.doesNotMatch(
    authFunction.Properties.FunctionCode,
    /import\s+crypto\s+from/,
  );
  assert.match(authFunction.Properties.FunctionCode, /code_challenge_method=S256/);
  assert.match(authFunction.Properties.FunctionCode, /crypto\.createHash\('sha256'\)/);
  assert.match(authFunction.Properties.FunctionCode, /tf_pkce_verifier/);
  assert.match(authFunction.Properties.FunctionCode, /applicationOrigin\(request\)/);
  assert.match(authFunction.Properties.FunctionCode, /isServiceRoute\(uri\)/);
  assert.match(authFunction.Properties.FunctionCode, /staticExportPath\(uri\)/);
  assert.match(
    authFunction.Properties.FunctionCode,
    /request\.uri = CONFIG\.callbackPath \+ '\/index\.html'/,
  );
  assert.match(authFunction.Properties.FunctionCode, /tf_oauth_client/);
  assert.match(authFunction.Properties.FunctionCode, /tf_oauth_domain/);
  assert.doesNotMatch(authFunction.Properties.FunctionCode, /response_type=token/);
});

test('auth gate maps static-export routes to their exact Next HTML shells', () => {
  const value = template();
  const authFunction = Object.values(
    value.findResources('AWS::CloudFront::Function'),
  )[0] as {
    Properties: { FunctionCode: string };
  };
  const code = authFunction.Properties.FunctionCode;
  for (const staticRoute of [
    '/applications',
    '/applications/new',
    '/auth/callback',
    '/configure',
    '/new-run',
    '/paused-runs',
  ]) {
    assert.match(code, new RegExp(`'${staticRoute.replace('/', '\\/')}'`));
  }
  assert.match(code, /if \(route === '\/'\) \{\s+return '\/index\.html';/);
  assert.match(
    code,
    /STATIC_ROUTES\.indexOf\(route\) !== -1\) \{\s+return route \+ '\/index\.html';/,
  );
  for (const shell of [
    '/applications/__shell__/index.html',
    '/applications/__shell__/runs/new/index.html',
    '/applications/__shell__/versions/__shell__/index.html',
    '/applications/__shell__/versions/__shell__/logs/index.html',
    '/applications/__shell__/versions/__shell__/threats/__shell__/index.html',
    '/runs/__shell__/progress/index.html',
  ]) {
    assert.match(code, new RegExp(`return '${shell.replaceAll('/', '\\/')}';`));
  }
  assert.match(code, /: staticExportPath\(uri\);/);
  assert.doesNotMatch(code, /request\.querystring\s*=/);
});

test('auth gate rewrites dynamic Next route data requests to exported shells', () => {
  const value = template();
  const authFunction = Object.values(
    value.findResources('AWS::CloudFront::Function'),
  )[0] as {
    Properties: { FunctionCode: string };
  };
  const code = authFunction.Properties.FunctionCode;
  assert.match(code, /function isRouteData\(uri\)/);
  assert.match(code, /uri\.endsWith\('\/index\.txt'\)/);
  assert.match(
    code,
    /return staticExportPath\(route\)\.replace\(\/\\\.html\$\/, '\.txt'\);/,
  );
  assert.match(code, /isStaticAsset\(uri\) && !isRouteData\(uri\)/);
  assert.match(
    code,
    /request\.uri = isRouteData\(uri\)\s+\? staticExportDataPath\(uri\)\s+: staticExportPath\(uri\);/,
  );
});

test('deployed auth gate routes historical log navigation and route data while preserving authentication', () => {
  const authFunction = Object.values(
    template().findResources('AWS::CloudFront::Function'),
  )[0] as { Properties: { FunctionCode: string } };
  const handler = runInNewContext(`${authFunction.Properties.FunctionCode}; handler`, {
    require: (name: string) => {
      assert.equal(name, 'crypto');
      return crypto;
    },
  }) as (event: Record<string, unknown>) => { uri?: string; statusCode?: number };
  const route = '/applications/app_test/versions/run_test/logs';
  const event = (uri: string, authenticated = true) => ({
    context: { requestId: 'route-test' },
    request: {
      uri, method: 'GET', clientIp: '127.0.0.1', querystring: {},
      headers: { host: { value: 'threatforest.example' } },
      cookies: authenticated ? { tf_session: { value: '1' } } : {},
    },
  });
  for (const uri of [route, `${route}/`]) {
    assert.equal(handler(event(uri)).uri, '/applications/__shell__/versions/__shell__/logs/index.html');
  }
  assert.equal(handler(event(`${route}/index.txt`)).uri, '/applications/__shell__/versions/__shell__/logs/index.txt');
  assert.equal(handler(event(route, false)).statusCode, 302);
  assert.equal(handler(event(`${route}/index.txt`, false)).statusCode, 401);
});

interface EdgeValue {
  value: string;
  attributes?: string;
  multiValue?: Array<{ value: string }>;
}

type EdgeValues = Record<string, EdgeValue>;
interface EdgeResult {
  uri?: string;
  statusCode?: number;
  body?: string;
  headers?: EdgeValues;
  cookies?: EdgeValues;
}

function authFixture() {
  const authFunction = Object.values(
    template().findResources('AWS::CloudFront::Function'),
  )[0] as { Properties: { FunctionCode: string } };
  const code = authFunction.Properties.FunctionCode;
  assert.ok(Buffer.byteLength(code) <= 10_240, 'CloudFront function must fit its 10 KB quota');
  const handler = runInNewContext(`${code}; handler`, {
    require: (name: string) => {
      assert.equal(name, 'crypto');
      return crypto;
    },
  }) as (event: Record<string, unknown>) => EdgeResult;
  let sequence = 0;
  const cookies: EdgeValues = {};
  const send = (
    uri: string,
    querystring: EdgeValues = {},
    headers: EdgeValues = {},
    method = 'GET',
  ): EdgeResult => handler({
    context: { requestId: `auth-test-${++sequence}` },
    request: {
      uri, method, clientIp: '127.0.0.1', querystring, cookies,
      headers: { host: { value: 'threatforest.example' }, ...headers },
    },
  });
  const apply = (response: EdgeResult) => {
    for (const [name, cookie] of Object.entries(response.cookies ?? {})) {
      if (cookie.attributes?.includes('Max-Age=0')) delete cookies[name];
      else cookies[name] = { value: cookie.value };
    }
  };
  const login = () => {
    const response = send('/');
    assert.equal(response.statusCode, 302);
    const authorization = new URL(response.headers!.location!.value);
    const state = authorization.searchParams.get('state')!;
    assert.match(state, /^[A-Za-z0-9_-]{43}$/);
    const verifier = response.cookies![`tf_pkce_verifier_${state}`]!;
    assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(authorization.searchParams.get('code_challenge'),
      crypto.createHash('sha256').update(verifier.value).digest('base64url'));
    assert.match(response.cookies![`tf_oauth_state_${state}`]!.attributes!, /HttpOnly/);
    assert.match(verifier.attributes!, /Secure; Path=\/; SameSite=Lax; Max-Age=600/);
    assert.doesNotMatch(verifier.attributes!, /HttpOnly/);
    apply(response);
    return state;
  };
  const callback = (state: string, uri = '/auth/callback') => send(uri, {
    code: { value: 'test-code' }, state: { value: state },
  });
  return { cookies, send, apply, login, callback };
}

test('concurrent login attempts keep independent state and PKCE cookies', () => {
  const fixture = authFixture();
  const first = fixture.login();
  const second = fixture.login();
  assert.notEqual(first, second);
  assert.equal(fixture.callback(first).uri, '/auth/callback/index.html');
  assert.equal(fixture.callback(second).uri, '/auth/callback/index.html');
  // The first tab consumes only its verifier after its token exchange.
  delete fixture.cookies[`tf_pkce_verifier_${first}`];
  assert.equal(fixture.callback(first).statusCode, 400);
  assert.equal(fixture.callback(second).uri, '/auth/callback/index.html');
});

test('unauthenticated API, WebSocket, route data, and prefetch requests cannot overwrite a login', () => {
  const fixture = authFixture();
  const state = fixture.login();
  const initialCookies = JSON.stringify(fixture.cookies);
  const requests = [
    fixture.send('/api/health'),
    fixture.send('/ws'),
    fixture.send('/applications/index.txt'),
    fixture.send('/applications', {}, { 'next-router-prefetch': { value: '1' } }),
    fixture.send('/applications', {}, { rsc: { value: '1' } }),
    fixture.send('/applications', {}, { purpose: { value: 'prefetch' } }),
    fixture.send('/applications', {}, { 'sec-purpose': { value: 'prefetch;prerender' } }),
    fixture.send('/', {}, {}, 'POST'),
  ];
  for (const response of requests) {
    assert.equal(response.statusCode, 401);
    assert.equal(response.cookies, undefined);
    assert.equal(response.headers?.location, undefined);
    assert.equal(response.headers?.['cache-control']?.value, 'no-store');
    fixture.apply(response);
  }
  assert.equal(JSON.stringify(fixture.cookies), initialCookies);
  assert.equal(fixture.callback(state).uri, '/auth/callback/index.html');
  fixture.cookies.tf_session = { value: '1' };
  assert.equal(fixture.send('/api/health').uri, '/api/health');
  assert.equal(fixture.send('/ws').uri, '/production');
});

test('invalid and expired callbacks fail closed with a fixed recovery link on every callback path', () => {
  const fixture = authFixture();
  const state = fixture.login();
  const code = { value: 'untrusted-code-not-to-reflect' };
  const requests = [
    fixture.send('/auth/callback', { state: { value: state } }),
    fixture.send('/auth/callback', { code }),
    fixture.send('/auth/callback', { code, state: { value: 'x'.repeat(43) } }),
    fixture.send('/auth/callback', { code, state: { value: state }, error: { value: 'access_denied' } }),
    fixture.send('/auth/callback', { code, state: { value: state, multiValue: [{ value: state }, { value: state }] } }),
    fixture.send('/auth/callback', { code: { ...code, multiValue: [code, code] }, state: { value: state } }),
    fixture.send('/auth/callback', { code, state: { value: state } }, {}, 'POST'),
  ];
  for (const uri of ['/auth/callback', '/auth/callback/', '/auth/callback/index.html']) {
    assert.equal(fixture.callback(state, uri).uri, '/auth/callback/index.html');
    requests.push(fixture.callback('expired', uri));
  }
  delete fixture.cookies[`tf_oauth_state_${state}`];
  requests.push(fixture.callback(state));
  for (const response of requests) {
    assert.equal(response.statusCode, 400);
    assert.match(response.body!, /href="\/auth\/login"/);
    assert.doesNotMatch(response.body!, /untrusted-code-not-to-reflect|access_denied/);
    assert.equal(response.headers?.['cache-control']?.value, 'no-store');
    assert.equal(response.headers?.['referrer-policy']?.value, 'no-referrer');
    assert.equal(response.cookies, undefined);
  }
});

test('logins issued before the deployment still require matching legacy state and verifier', () => {
  const fixture = authFixture();
  const state = 'a'.repeat(43);
  fixture.cookies.tf_oauth_state = { value: state };
  fixture.cookies.tf_pkce_verifier = { value: 'legacy-verifier' };
  fixture.login();
  assert.equal(fixture.callback(state).uri, '/auth/callback/index.html');
  assert.equal(fixture.callback('b'.repeat(43)).statusCode, 400);
  delete fixture.cookies.tf_pkce_verifier;
  assert.equal(fixture.callback(state).statusCode, 400);
});

test('pending logins are bounded, logout removes them, and recovery can start with an existing session', () => {
  const fixture = authFixture();
  let state = '';
  for (let index = 0; index < 12; index += 1) state = fixture.login();
  assert.equal(Object.keys(fixture.cookies).filter(name => name.startsWith('tf_oauth_state_')).length, 8);
  assert.equal(Object.keys(fixture.cookies).filter(name => name.startsWith('tf_pkce_verifier_')).length, 8);
  assert.equal(fixture.callback(state).uri, '/auth/callback/index.html');
  fixture.cookies.tf_session = { value: '1' };
  const restart = fixture.send('/auth/login', { next: { value: 'https://untrusted.example' } });
  assert.equal(restart.statusCode, 302);
  const url = new URL(restart.headers!.location!.value);
  assert.equal(url.searchParams.get('redirect_uri'), 'https://threatforest.example/auth/callback');
  assert.equal(url.searchParams.get('next'), null);
  fixture.apply(fixture.send('/auth/logout'));
  assert.equal(Object.keys(fixture.cookies).length, 0);
});

test('authenticated WebSocket paths select the behavior then rewrite to the exact stage path', () => {
  const value = template();
  const authFunction = Object.values(
    value.findResources('AWS::CloudFront::Function'),
  )[0] as {
    Properties: { FunctionCode: string };
  };
  assert.match(
    authFunction.Properties.FunctionCode,
    /"webSocketStagePath":"\/production"/,
  );
  assert.match(
    authFunction.Properties.FunctionCode,
    /if \(isWebSocketRoute\(uri\)\) \{\s+request\.uri = CONFIG\.webSocketStagePath;\s+return request;/,
  );
  assert.match(
    authFunction.Properties.FunctionCode,
    /if \(isServiceRoute\(uri\)\) \{\s+return request;/,
  );
  assert.doesNotMatch(
    authFunction.Properties.FunctionCode,
    /request\.uri = '\/ws/,
  );
  const distribution = Object.values(
    value.findResources('AWS::CloudFront::Distribution'),
  )[0] as {
    Properties: {
      DistributionConfig: {
        Origins: Array<{
          DomainName: string;
          OriginPath?: string;
        }>;
      };
    };
  };
  const webSocketOrigin =
    distribution.Properties.DistributionConfig.Origins.find(
      ({ DomainName }) => DomainName.includes('ws-id.execute-api'),
    );
  assert.ok(webSocketOrigin);
  assert.equal(webSocketOrigin.OriginPath, undefined);
});

test('WebSocket stage paths reject a trailing slash that API Gateway cannot route', () => {
  const app = new App();
  const imports = new Stack(app, 'InvalidPathImports');
  assert.throws(
    () =>
      new EdgeStack(app, 'InvalidWebSocketPath', {
        env: { account: '123456789012', region: 'eu-west-2' },
        webBucket: s3.Bucket.fromBucketName(
          imports,
          'InvalidPathBucket',
          'threatforest-test-web-fixture',
        ),
        webAclArn:
          'arn:aws:wafv2:us-east-1:123456789012:global/webacl/threatforest-test-edge/example',
        authentication: {
          managedLoginBaseUrl:
            'https://threatforest-test.auth.eu-west-2.amazoncognito.com',
          userPoolClientId: 'exampleclientid',
        },
        webSocketOrigin: {
          domainName: 'ws-id.execute-api.eu-west-2.amazonaws.com',
          originPath: '/production/',
        },
      }),
    /must not end with a slash/,
  );
});

test('responses receive CSP, HSTS, frame, referrer, and browser capability headers', () => {
  const value = template();
  value.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
    ResponseHeadersPolicyConfig: {
      Name: 'threatforest-test-security',
      SecurityHeadersConfig: Match.objectLike({
        ContentSecurityPolicy: Match.objectLike({
          ContentSecurityPolicy: Match.stringLikeRegexp(
            "default-src 'self'.*frame-ancestors 'none'",
          ),
          Override: true,
        }),
        ContentTypeOptions: { Override: true },
        FrameOptions: { FrameOption: 'DENY', Override: true },
        ReferrerPolicy: { ReferrerPolicy: 'no-referrer', Override: true },
        StrictTransportSecurity: Match.objectLike({
          AccessControlMaxAgeSec: 31536000,
          Override: true,
        }),
      }),
      CustomHeadersConfig: {
        Items: Match.arrayWith([
          Match.objectLike({ Header: 'Permissions-Policy', Override: true }),
          Match.objectLike({ Header: 'Cross-Origin-Opener-Policy', Override: true }),
        ]),
      },
    },
  });
});

test('CSP permits direct uploads only to the configured artifact bucket origin', () => {
  const value = template();
  const responseHeadersPolicy = Object.values(
    value.findResources('AWS::CloudFront::ResponseHeadersPolicy'),
  )[0] as {
    Properties: {
      ResponseHeadersPolicyConfig: {
        SecurityHeadersConfig: {
          ContentSecurityPolicy: {
            ContentSecurityPolicy: string;
          };
        };
      };
    };
  };
  const policy =
    responseHeadersPolicy.Properties.ResponseHeadersPolicyConfig
      .SecurityHeadersConfig.ContentSecurityPolicy.ContentSecurityPolicy;
  assert.match(
    policy,
    /connect-src 'self' https:\/\/\*\.amazoncognito\.com https:\/\/cognito-idp\.eu-west-2\.amazonaws\.com wss: https:\/\/threatforest-artifacts\.s3\.eu-west-2\.amazonaws\.com/,
  );
  assert.doesNotMatch(policy, /https:\/\/\*\.s3\.eu-west-2\.amazonaws\.com/);
});

test('web deployment logs are encrypted and CloudFront delivery is configured outside the regional stack', () => {
  const value = template();
  value.hasResourceProperties('AWS::Logs::LogGroup', {
    LogGroupName: '/threatforest/test/web-deployment',
    KmsKeyId: Match.anyValue(),
    RetentionInDays: 365,
  });
  value.hasResourceProperties('AWS::KMS::Key', {
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Sid: 'AllowCloudWatchLogsEncryption',
          Principal: {
            Service: Match.anyValue(),
          },
          Action: Match.arrayWith([
            'kms:Decrypt',
            'kms:GenerateDataKey*',
          ]),
          Condition: {
            ArnLike: {
              'kms:EncryptionContext:aws:logs:arn':
                Match.anyValue(),
            },
          },
        }),
      ]),
    },
  });
  value.resourceCountIs('AWS::Logs::DeliverySource', 0);
  value.resourceCountIs('AWS::Logs::DeliveryDestination', 0);
  value.resourceCountIs('AWS::Logs::Delivery', 0);
});

test('generated CloudFront domains are registered after creation and use an encrypted web bucket', () => {
  const app = new App();
  const env = { account: '123456789012', region: 'eu-west-2' };
  const dependencies = new Stack(app, 'EdgeDependencies', { env });
  const buildKey = new kms.Key(dependencies, 'BuildKey');
  const telemetryKey = new kms.Key(dependencies, 'TelemetryKey');
  const accessLogs = new s3.Bucket(dependencies, 'AccessLogs');
  const callbackLogs = new logs.LogGroup(dependencies, 'CallbackLogs', {
    encryptionKey: telemetryKey,
  });
  const stack = new EdgeStack(app, 'GeneratedDomainEdge', {
    env,
    webBucketEncryptionKey: buildKey,
    webAccessLogsBucket: accessLogs,
    webAclArn:
      'arn:aws:wafv2:us-east-1:123456789012:global/webacl/threatforest-test-edge/example',
    authentication: {
      managedLoginBaseUrl:
        'https://threatforest-test.auth.eu-west-2.amazoncognito.com',
      userPoolClientId: 'exampleclientid',
    },
    callbackRegistration: {
      userPoolId: 'eu-west-2_example',
      logGroup: callbackLogs,
      environmentEncryptionKey: telemetryKey,
    },
  });
  const value = Template.fromStack(stack);
  value.hasResourceProperties('AWS::S3::Bucket', {
    BucketEncryption: Match.anyValue(),
    PublicAccessBlockConfiguration: Match.objectLike({
      BlockPublicPolicy: true,
    }),
    VersioningConfiguration: { Status: 'Enabled' },
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Code: {
      ZipFile: Match.stringLikeRegexp('UpdateUserPoolClient'),
    },
    Runtime: 'python3.13',
  });
  const templateText = JSON.stringify(value.toJSON());
  assert.match(templateText, /CallbackUrl/);
  assert.match(templateText, /"DomainName"/);
});
