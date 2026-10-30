import {
  ArnFormat,
  CustomResource,
  Duration,
  RemovalPolicy,
  Size,
  Stack,
  Token,
  type StackProps,
  aws_certificatemanager as acm,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_iam as iam,
  aws_kms as kms,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_s3 as s3,
  aws_s3_deployment as s3deployment,
  custom_resources as customResources,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';

export interface CognitoSpaAuthentication {
  readonly managedLoginBaseUrl: string;
  readonly userPoolClientId: string;
  readonly callbackUrl?: string;
  readonly logoutUrl?: string;
  readonly callbackPath?: string;
  readonly logoutPath?: string;
  readonly sessionCookieName?: string;
}

export interface HostedServiceOrigin {
  readonly domainName: string;
  readonly originPath?: string;
  readonly customHeaders?: Record<string, string>;
}

export interface CognitoCallbackRegistration {
  readonly userPoolId: string;
  readonly logGroup: logs.ILogGroup;
  readonly environmentEncryptionKey: kms.IKey;
}

export interface EdgeStackProps extends StackProps {
  readonly webBucket?: s3.IBucket;
  readonly webBucketEncryptionKey?: kms.IKey;
  readonly webAccessLogsBucket?: s3.IBucket;
  readonly webAclArn: string;
  readonly authentication: CognitoSpaAuthentication;
  readonly callbackRegistration?: CognitoCallbackRegistration;
  readonly apiOrigin?: HostedServiceOrigin;
  readonly webSocketOrigin?: HostedServiceOrigin;
  readonly deploymentLogGroup?: logs.ILogGroup;
  readonly deploymentLogEncryptionKey?: kms.IKey;
  readonly certificate?: acm.ICertificate;
  readonly domainNames?: string[];
  readonly additionalConnectSources?: string[];
  readonly webAssetPath?: string;
}

function validatePath(name: string, path: string): void {
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) {
    throw new Error(`${name} must be an absolute path without a query string or fragment`);
  }
}

function validateAuthentication(config: CognitoSpaAuthentication): Required<
  Pick<CognitoSpaAuthentication, 'callbackPath' | 'logoutPath' | 'sessionCookieName'>
> {
  const callbackPath = config.callbackPath ?? '/auth/callback';
  const logoutPath = config.logoutPath ?? '/auth/logout';
  const sessionCookieName = config.sessionCookieName ?? 'tf_session';
  validatePath('callbackPath', callbackPath);
  validatePath('logoutPath', logoutPath);

  if (!/^[A-Za-z0-9_-]+$/.test(sessionCookieName)) {
    throw new Error('sessionCookieName contains unsupported characters');
  }

  for (const [name, value] of [
    ['callbackUrl', config.callbackUrl],
    ['logoutUrl', config.logoutUrl],
  ] as const) {
    if (value === undefined) continue;
    if (!Token.isUnresolved(value) && !value.startsWith('https://')) {
      throw new Error(`${name} must use HTTPS`);
    }
  }

  if (config.callbackUrl !== undefined && !Token.isUnresolved(config.callbackUrl)) {
    const registeredPath = new URL(config.callbackUrl).pathname;
    if (registeredPath !== callbackPath) {
      throw new Error(`callbackPath ${callbackPath} does not match callbackUrl ${registeredPath}`);
    }
  }
  if (config.logoutUrl !== undefined && !Token.isUnresolved(config.logoutUrl)) {
    const registeredPath = new URL(config.logoutUrl).pathname;
    if (registeredPath !== logoutPath) {
      throw new Error(`logoutPath ${logoutPath} does not match logoutUrl ${registeredPath}`);
    }
  }

  return { callbackPath, logoutPath, sessionCookieName };
}

function authGateCode(
  config: CognitoSpaAuthentication,
  resolved: ReturnType<typeof validateAuthentication>,
  webSocketStagePath: string,
): string {
  const runtimeConfig = JSON.stringify({
    managedLoginBaseUrl: config.managedLoginBaseUrl,
    userPoolClientId: config.userPoolClientId,
    callbackPath: resolved.callbackPath,
    logoutPath: resolved.logoutPath,
    sessionCookieName: resolved.sessionCookieName,
    webSocketStagePath,
  });

  return `
const crypto = require('crypto');

const CONFIG = ${runtimeConfig};
const STATIC_ASSET = /\\.(?:avif|css|gif|ico|jpeg|jpg|js|json|map|mjs|png|svg|txt|webmanifest|webp|woff|woff2)$/i;
const STATIC_ROUTES = [
  '/applications',
  '/applications/new',
  '/auth/callback',
  '/configure',
  '/new-run',
  '/paused-runs',
];

function cookieValue(cookies, name) {
  const cookie = cookies && cookies[name];
  return cookie && !cookie.multiValue ? cookie.value : '';
}

function queryValue(query, name) {
  const parameter = query && query[name];
  return parameter && !parameter.multiValue ? parameter.value : '';
}

function expireOAuthFlows(cookies, keep) {
  const expired = {};
  const names = Object.keys(cookies || {}).filter(name => /^tf_oauth_state_[A-Za-z0-9_-]{43}$/.test(name));
  for (let index = 0; index < names.length - keep; index += 1) {
    const name = names[index];
    expired[name] = { value: '', attributes: 'Secure; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' };
    expired['tf_pkce_verifier_' + name.slice('tf_oauth_state_'.length)] =
      { value: '', attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=0' };
  }
  return expired;
}

function invalidCallback() {
  return {
    statusCode: 400,
    statusDescription: 'Bad Request',
    headers: {
      'cache-control': { value: 'no-store' },
      'content-type': { value: 'text/html; charset=utf-8' },
      'referrer-policy': { value: 'no-referrer' },
      'content-security-policy': { value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" },
    },
    body: '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in again - ThreatForest</title><main><h1>Sign in again</h1><p>This sign-in attempt expired or could not be verified. Start a new sign-in from ThreatForest.</p><p><a href="/auth/login">Sign in to ThreatForest</a></p></main></html>',
  };
}

function constantTimeEquals(left, right) {
  if (!left || !right || left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function isStaticAsset(uri) {
  return uri.startsWith('/_next/static/') || STATIC_ASSET.test(uri);
}

function isRouteData(uri) {
  return uri.endsWith('/index.txt');
}

function isServiceRoute(uri) {
  return uri === '/api' || uri.startsWith('/api/') || uri === '/ws' || uri.startsWith('/ws/');
}

function isWebSocketRoute(uri) {
  return uri === '/ws' || uri.startsWith('/ws/');
}

function staticExportPath(uri) {
  const route = uri.length > 1 ? uri.replace(/\\/+$/, '') : uri;
  if (route === '/') {
    return '/index.html';
  }
  if (STATIC_ROUTES.indexOf(route) !== -1) {
    return route + '/index.html';
  }

  const segments = route.split('/').filter(Boolean);
  if (segments.length === 2 && segments[0] === 'applications') {
    return '/applications/__shell__/index.html';
  }
  if (
    segments.length === 4 &&
    segments[0] === 'applications' &&
    segments[2] === 'runs' &&
    segments[3] === 'new'
  ) {
    return '/applications/__shell__/runs/new/index.html';
  }
  if (
    segments.length === 4 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions'
  ) {
    return '/applications/__shell__/versions/__shell__/index.html';
  }
  if (
    segments.length === 5 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions' &&
    segments[4] === 'logs'
  ) {
    return '/applications/__shell__/versions/__shell__/logs/index.html';
  }
  if (
    segments.length === 6 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions' &&
    segments[4] === 'threats'
  ) {
    return '/applications/__shell__/versions/__shell__/threats/__shell__/index.html';
  }
  if (
    segments.length === 3 &&
    segments[0] === 'runs' &&
    segments[2] === 'progress'
  ) {
    return '/runs/__shell__/progress/index.html';
  }
  return '/index.html';
}

function staticExportDataPath(uri) {
  const route = uri.slice(0, -'/index.txt'.length) || '/';
  return staticExportPath(route).replace(/\\.html$/, '.txt');
}

function applicationOrigin(request) {
  const host = request.headers && request.headers.host ? request.headers.host.value : '';
  if (!/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(host)) {
    return '';
  }
  return 'https://' + host;
}

function redirect(location, cookies) {
  return {
    statusCode: 302,
    statusDescription: 'Found',
    headers: {
      location: { value: location },
      'cache-control': { value: 'no-store' },
    },
    cookies,
  };
}

function handler(event) {
  const request = event.request;
  const uri = request.uri;
  const origin = applicationOrigin(request);

  if (uri === CONFIG.logoutPath) {
    const expired = 'Secure; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';
    if (!origin) {
      return { statusCode: 400, statusDescription: 'Bad Request' };
    }
    const logoutUrl =
      CONFIG.managedLoginBaseUrl.replace(/\\/+$/, '') +
      '/logout?client_id=' + encodeURIComponent(CONFIG.userPoolClientId) +
      '&logout_uri=' + encodeURIComponent(origin + '/');
    return redirect(logoutUrl, Object.assign(expireOAuthFlows(request.cookies, 0), {
      [CONFIG.sessionCookieName]: { value: '', attributes: expired },
      tf_oauth_state: { value: '', attributes: expired },
      tf_pkce_verifier: { value: '', attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=0' },
      tf_oauth_client: { value: '', attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=0' },
      tf_oauth_domain: { value: '', attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=0' },
    }));
  }

  if (uri === CONFIG.callbackPath || uri === CONFIG.callbackPath + '/' || uri === CONFIG.callbackPath + '/index.html') {
    const state = queryValue(request.querystring, 'state');
    const scopedState = cookieValue(request.cookies, 'tf_oauth_state_' + state);
    const expectedState = scopedState || cookieValue(request.cookies, 'tf_oauth_state');
    const verifier = cookieValue(request.cookies, scopedState ? 'tf_pkce_verifier_' + state : 'tf_pkce_verifier');
    const code = queryValue(request.querystring, 'code');
    if (request.method !== 'GET' || !code || request.querystring.error ||
        !/^[A-Za-z0-9_-]{43}$/.test(state) || !verifier || !constantTimeEquals(state, expectedState)) {
      return invalidCallback();
    }
    request.uri = CONFIG.callbackPath + '/index.html';
    return request;
  }

  if (isStaticAsset(uri) && !isRouteData(uri)) {
    return request;
  }

  if (uri === '/auth/login' || !cookieValue(request.cookies, CONFIG.sessionCookieName)) {
    if (isServiceRoute(uri) || isRouteData(uri) || request.method !== 'GET' ||
        cookieValue(request.headers, 'next-router-prefetch') || cookieValue(request.headers, 'rsc') ||
        cookieValue(request.headers, 'purpose') === 'prefetch' ||
        cookieValue(request.headers, 'sec-purpose').includes('prefetch')) {
      return {
        statusCode: 401,
        statusDescription: 'Unauthorized',
        headers: {
          'cache-control': { value: 'no-store' },
          'content-type': { value: 'application/json' },
        },
        body: '{"message":"Sign in to ThreatForest to continue."}',
      };
    }
    if (!origin) {
      return { statusCode: 400, statusDescription: 'Bad Request' };
    }
    const seed = event.context.requestId + ':' + request.clientIp + ':' + Date.now();
    const verifier = crypto.createHash('sha256').update(seed).digest('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const state = crypto.createHash('sha256').update('state:' + seed).digest('base64url');
    const authorizeUrl =
      CONFIG.managedLoginBaseUrl.replace(/\\/+$/, '') +
      '/oauth2/authorize?response_type=code' +
      '&client_id=' + encodeURIComponent(CONFIG.userPoolClientId) +
      '&redirect_uri=' + encodeURIComponent(origin + CONFIG.callbackPath) +
      '&scope=' + encodeURIComponent('openid email profile') +
      '&state=' + encodeURIComponent(state) +
      '&code_challenge=' + encodeURIComponent(challenge) +
      '&code_challenge_method=S256';

    return redirect(authorizeUrl, Object.assign(expireOAuthFlows(request.cookies, 7), {
      ['tf_oauth_state_' + state]: {
        value: state,
        attributes: 'Secure; Path=/; HttpOnly; SameSite=Lax; Max-Age=600',
      },
      ['tf_pkce_verifier_' + state]: {
        value: verifier,
        attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=600',
      },
      tf_oauth_client: {
        value: CONFIG.userPoolClientId,
        attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=2592000',
      },
      tf_oauth_domain: {
        value: encodeURIComponent(CONFIG.managedLoginBaseUrl),
        attributes: 'Secure; Path=/; SameSite=Lax; Max-Age=2592000',
      },
    }));
  }

  if (isWebSocketRoute(uri)) {
    request.uri = CONFIG.webSocketStagePath;
    return request;
  }

  if (isServiceRoute(uri)) {
    return request;
  }

  request.uri = isRouteData(uri)
    ? staticExportDataPath(uri)
    : staticExportPath(uri);
  return request;
}
`.trim();
}

const CALLBACK_REGISTRATION_CODE = `
import boto3

client = boto3.client("cognito-idp")

def handler(event, _context):
    props = event["ResourceProperties"]
    user_pool_id = props["UserPoolId"]
    client_id = props["ClientId"]
    physical_id = "threatforest-cognito-callbacks-" + client_id
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id}

    current = client.describe_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id,
    )["UserPoolClient"]
    allowed = set(
        client.meta.service_model.operation_model("UpdateUserPoolClient")
        .input_shape.members.keys()
    )
    request = {
        key: value
        for key, value in current.items()
        if key in allowed and value is not None
    }
    request["UserPoolId"] = user_pool_id
    request["ClientId"] = client_id
    request["CallbackURLs"] = [props["CallbackUrl"]]
    request["LogoutURLs"] = [props["ApplicationUrl"], props["LogoutUrl"]]
    request["DefaultRedirectURI"] = props["CallbackUrl"]
    client.update_user_pool_client(**request)
    return {
        "PhysicalResourceId": physical_id,
        "Data": {"CallbackUrl": props["CallbackUrl"]},
    }
`.trim();

function registerGeneratedDomainCallbacks(
  scope: Construct,
  registration: CognitoCallbackRegistration,
  clientId: string,
  applicationUrl: string,
  callbackPath: string,
  logoutPath: string,
  distribution: cloudfront.Distribution,
): void {
  const handler = new lambda.Function(scope, 'CognitoCallbackRegistrationHandler', {
    runtime: lambda.Runtime.PYTHON_3_13,
    handler: 'index.handler',
    code: lambda.Code.fromInline(CALLBACK_REGISTRATION_CODE),
    timeout: Duration.minutes(2),
    logGroup: registration.logGroup,
    environmentEncryption: registration.environmentEncryptionKey,
  });
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: [
        'cognito-idp:DescribeUserPoolClient',
        'cognito-idp:UpdateUserPoolClient',
      ],
      resources: [
        Stack.of(scope).formatArn({
          service: 'cognito-idp',
          resource: 'userpool',
          resourceName: registration.userPoolId,
          arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
        }),
      ],
    }),
  );
  const provider = new customResources.Provider(scope, 'CognitoCallbackRegistrationProvider', {
    onEventHandler: handler,
    logGroup: registration.logGroup,
    providerFunctionEnvEncryption: registration.environmentEncryptionKey,
  });
  const registrationResource = new CustomResource(scope, 'CognitoCallbackRegistration', {
    serviceToken: provider.serviceToken,
    properties: {
      UserPoolId: registration.userPoolId,
      ClientId: clientId,
      ApplicationUrl: `${applicationUrl}/`,
      CallbackUrl: `${applicationUrl}${callbackPath}`,
      LogoutUrl: `${applicationUrl}${logoutPath}`,
    },
  });
  registrationResource.node.addDependency(distribution);
}

export class EdgeStack extends Stack {
  readonly distribution: cloudfront.Distribution;
  readonly webBucket: s3.IBucket;
  readonly authGate: cloudfront.Function;
  readonly responseHeadersPolicy: cloudfront.ResponseHeadersPolicy;
  readonly deploymentLogGroup: logs.ILogGroup;
  readonly deploymentLogEncryptionKey?: kms.IKey;
  readonly applicationUrl: string;
  readonly cognitoLogoutUrl: string;

  constructor(scope: Construct, id: string, props: EdgeStackProps) {
    super(scope, id, props);

    const auth = validateAuthentication(props.authentication);
    const webSocketStagePath = props.webSocketOrigin?.originPath ?? '/';
    validatePath('webSocketOrigin.originPath', webSocketStagePath);
    if (webSocketStagePath.length > 1 && webSocketStagePath.endsWith('/')) {
      throw new Error('webSocketOrigin.originPath must not end with a slash');
    }
    if ((props.certificate && !props.domainNames?.length) || (!props.certificate && props.domainNames?.length)) {
      throw new Error('certificate and domainNames must be supplied together');
    }
    if (props.deploymentLogGroup && props.deploymentLogEncryptionKey) {
      throw new Error(
        'Supply either deploymentLogGroup or deploymentLogEncryptionKey, not both',
      );
    }

    if (!props.webBucket && !props.webBucketEncryptionKey) {
      throw new Error('webBucketEncryptionKey is required when EdgeStack creates the web bucket');
    }
    this.webBucket =
      props.webBucket ??
      new s3.Bucket(this, 'WebBucket', {
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: props.webBucketEncryptionKey,
        bucketKeyEnabled: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true,
        objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        versioned: true,
        serverAccessLogsBucket: props.webAccessLogsBucket,
        serverAccessLogsPrefix: props.webAccessLogsBucket ? 'web/' : undefined,
        removalPolicy: RemovalPolicy.RETAIN,
        lifecycleRules: [{ noncurrentVersionExpiration: Duration.days(365) }],
      });

    this.authGate = new cloudfront.Function(this, 'CognitoAuthGate', {
      functionName: `${DEPLOYMENT.namePrefix}-cognito-auth-gate`,
      comment: 'PKCE redirect, callback validation, and authenticated SPA route rewriting',
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      code: cloudfront.FunctionCode.fromInline(
        authGateCode(props.authentication, auth, webSocketStagePath),
      ),
    });

    const connectSources = [
      "'self'",
      'https://*.amazoncognito.com',
      `https://cognito-idp.${this.region}.amazonaws.com`,
      'wss:',
      ...(props.additionalConnectSources ?? []),
    ];
    const contentSecurityPolicy = [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      `connect-src ${connectSources.join(' ')}`,
      "worker-src 'self' blob:",
      "form-action 'self' https://*.amazoncognito.com",
      'upgrade-insecure-requests',
    ].join('; ');

    this.responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(
      this,
      'SecurityResponseHeaders',
      {
        responseHeadersPolicyName: `${DEPLOYMENT.namePrefix}-security`,
        comment: 'ThreatForest browser security headers',
        securityHeadersBehavior: {
          contentSecurityPolicy: {
            contentSecurityPolicy,
            override: true,
          },
          contentTypeOptions: { override: true },
          frameOptions: {
            frameOption: cloudfront.HeadersFrameOption.DENY,
            override: true,
          },
          referrerPolicy: {
            referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
            override: true,
          },
          strictTransportSecurity: {
            accessControlMaxAge: Duration.days(365),
            includeSubdomains: true,
            preload: true,
            override: true,
          },
          xssProtection: {
            protection: false,
            override: true,
          },
        },
        customHeadersBehavior: {
          customHeaders: [
            {
              header: 'Permissions-Policy',
              value: 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
              override: true,
            },
            {
              header: 'Cross-Origin-Opener-Policy',
              value: 'same-origin',
              override: true,
            },
            {
              header: 'Cross-Origin-Resource-Policy',
              value: 'same-origin',
              override: true,
            },
          ],
        },
      },
    );

    const origin = origins.S3BucketOrigin.withOriginAccessControl(this.webBucket, {
      originAccessLevels: [cloudfront.AccessLevel.READ],
    });
    const authenticatedFunctionAssociation: cloudfront.FunctionAssociation = {
      function: this.authGate,
      eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
    };
    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};
    if (props.apiOrigin) {
      additionalBehaviors['api/*'] = {
        origin: new origins.HttpOrigin(props.apiOrigin.domainName, {
          originPath: props.apiOrigin.originPath,
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
          customHeaders: props.apiOrigin.customHeaders,
        }),
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: this.responseHeadersPolicy,
        functionAssociations: [authenticatedFunctionAssociation],
      };
    }
    if (props.webSocketOrigin) {
      additionalBehaviors['ws*'] = {
        origin: new origins.HttpOrigin(props.webSocketOrigin.domainName, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
          customHeaders: props.webSocketOrigin.customHeaders,
        }),
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: this.responseHeadersPolicy,
        functionAssociations: [authenticatedFunctionAssociation],
      };
    }
    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'ThreatForest authenticated SPA',
      defaultRootObject: 'index.html',
      defaultBehavior: {
        origin,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        compress: true,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: this.responseHeadersPolicy,
        functionAssociations: [authenticatedFunctionAssociation],
      },
      additionalBehaviors,
      certificate: props.certificate,
      domainNames: props.domainNames,
      webAclId: props.webAclArn,
      enableIpv6: true,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_ALL,
      publishAdditionalMetrics: true,
    });

    if (props.deploymentLogGroup) {
      this.deploymentLogGroup = props.deploymentLogGroup;
    } else {
      this.deploymentLogEncryptionKey =
        props.deploymentLogEncryptionKey ??
        new kms.Key(this, 'WebDeploymentLogKey', {
          alias: `alias/${DEPLOYMENT.namePrefix}/web-deployment-logs`,
          description: 'Encryption key for ThreatForest web deployment logs',
          enableKeyRotation: true,
          pendingWindow: Duration.days(30),
          removalPolicy: RemovalPolicy.RETAIN,
        });
      if (!props.deploymentLogEncryptionKey) {
        this.deploymentLogEncryptionKey.applyRemovalPolicy(RemovalPolicy.RETAIN);
      }
      this.deploymentLogEncryptionKey.addToResourcePolicy(
        new iam.PolicyStatement({
          sid: 'AllowCloudWatchLogsEncryption',
          principals: [
            new iam.ServicePrincipal(
              `logs.${this.region}.${this.urlSuffix}`,
            ),
          ],
          actions: [
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:ReEncrypt*',
            'kms:GenerateDataKey*',
            'kms:Describe*',
          ],
          resources: ['*'],
          conditions: {
            ArnLike: {
              'kms:EncryptionContext:aws:logs:arn': this.formatArn({
                service: 'logs',
                resource: 'log-group',
                resourceName: `/threatforest/${DEPLOYMENT.environment}/web-deployment`,
                arnFormat: ArnFormat.COLON_RESOURCE_NAME,
              }),
            },
          },
        }),
      );
      this.deploymentLogGroup = new logs.LogGroup(this, 'WebDeploymentLogs', {
        logGroupName: `/threatforest/${DEPLOYMENT.environment}/web-deployment`,
        encryptionKey: this.deploymentLogEncryptionKey,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN,
      });
    }

    this.applicationUrl = `https://${props.domainNames?.[0] ?? this.distribution.distributionDomainName}`;
    if (props.callbackRegistration) {
      registerGeneratedDomainCallbacks(
        this,
        props.callbackRegistration,
        props.authentication.userPoolClientId,
        this.applicationUrl,
        auth.callbackPath,
        auth.logoutPath,
        this.distribution,
      );
    }
    this.cognitoLogoutUrl =
      `${props.authentication.managedLoginBaseUrl.replace(/\/+$/, '')}/logout` +
      `?client_id=${props.authentication.userPoolClientId}` +
      `&logout_uri=${this.applicationUrl}/`;

    if (props.webAssetPath) {
      const deployment = new s3deployment.BucketDeployment(
        this,
        'WebDeployment',
        {
          destinationBucket: this.webBucket,
          sources: [s3deployment.Source.asset(props.webAssetPath)],
          prune: true,
          retainOnDelete: true,
          distribution: this.distribution,
          distributionPaths: ['/*'],
          logGroup: this.deploymentLogGroup,
          memoryLimit: 1024,
          ephemeralStorageSize: Size.gibibytes(2),
        },
      );
      deployment.node.addDependency(this.distribution);
    }
  }
}
