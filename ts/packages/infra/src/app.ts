#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { App, Tags } from 'aws-cdk-lib';
import { AgentCoreStack } from './agentcore-stack.js';
import { DEPLOYMENT } from './config.js';
import { resolveDeployment } from './deployment-config.mjs';
import { EdgeLoggingStack } from './edge-logging-stack.js';
import { EdgeStack } from './edge-stack.js';
import { FoundationStack } from './foundation-stack.js';
import { HostedServicesStack } from './hosted-services-stack.js';
import { IdentityStack } from './identity-stack.js';
import { ObservabilityStack } from './observability-stack.js';
import { WafStack } from './waf-stack.js';

const app = new App();
resolveDeployment(process.env, true);

const regionalEnvironment = {
  account: DEPLOYMENT.account,
  region: DEPLOYMENT.region,
};
const edgeEnvironment = {
  account: DEPLOYMENT.account,
  region: DEPLOYMENT.edgeRegion,
};
const configuredWebAssetPath = app.node.tryGetContext('webAssetPath') as
  | unknown
  | undefined;
if (
  configuredWebAssetPath !== undefined &&
  (typeof configuredWebAssetPath !== 'string' ||
    configuredWebAssetPath.trim() === '')
) {
  throw new Error('CDK context webAssetPath must be a non-empty string');
}
const webAssetPath =
  configuredWebAssetPath ??
  fileURLToPath(new URL('../../../web/out', import.meta.url));

const foundation = new FoundationStack(app, 'ThreatForestFoundation', {
  env: regionalEnvironment,
  description: 'ThreatForest hosted foundation resources',
  terminationProtection: true,
});
const identity = new IdentityStack(app, 'ThreatForestIdentity', {
  env: regionalEnvironment,
  callbackUrls: ['http://localhost:3000/auth/callback'],
  logoutUrls: ['http://localhost:3000/'],
  description: 'ThreatForest Cognito identity provider',
  terminationProtection: true,
});
const agentCore = new AgentCoreStack(app, 'ThreatForestAgentCore', {
  env: regionalEnvironment,
  foundation,
  userPool: identity.userPool,
  userPoolClient: identity.userPoolClient,
  description: 'ThreatForest AgentCore Runtime, Memory, Gateway, and Evaluations',
  terminationProtection: true,
});
const services = new HostedServicesStack(app, 'ThreatForestServices', {
  env: regionalEnvironment,
  foundation,
  identity,
  agentCore,
  description: 'ThreatForest authenticated API, ingestion, and workflows',
  terminationProtection: true,
});
const waf = new WafStack(app, 'ThreatForestWaf', {
  env: edgeEnvironment,
  description: 'ThreatForest CloudFront WAF',
  terminationProtection: true,
  crossRegionReferences: true,
});
const edge = new EdgeStack(app, 'ThreatForestEdge', {
  env: regionalEnvironment,
  crossRegionReferences: true,
  webAclArn: waf.webAclArn,
  webBucketEncryptionKey: foundation.keys.build,
  webAccessLogsBucket: foundation.accessLogsBucket,
  authentication: {
    managedLoginBaseUrl: identity.managedLoginBaseUrl,
    userPoolClientId: identity.userPoolClient.userPoolClientId,
  },
  callbackRegistration: {
    userPoolId: identity.userPool.userPoolId,
    logGroup: foundation.workflowLogGroup,
    environmentEncryptionKey: foundation.keys.workflows,
  },
  apiOrigin: {
    domainName: services.httpOriginDomain,
    customHeaders: {
      'x-threatforest-origin-verify':
        foundation.originCredential.secretValue.unsafeUnwrap(),
    },
  },
  webSocketOrigin: {
    domainName: services.webSocketOriginDomain,
    originPath: '/hosted',
    customHeaders: {
      'x-threatforest-origin-verify':
      foundation.originCredential.secretValue.unsafeUnwrap(),
    },
  },
  additionalConnectSources: [
    `https://${foundation.artifactsBucket.bucketRegionalDomainName}`,
  ],
  webAssetPath,
  description: 'ThreatForest authenticated CloudFront application',
  terminationProtection: true,
});
const edgeLogging = new EdgeLoggingStack(app, 'ThreatForestEdgeLogging', {
  env: edgeEnvironment,
  crossRegionReferences: true,
  distributionArn: edge.distribution.distributionArn,
  description: 'ThreatForest CloudFront standard logging v2 delivery',
  terminationProtection: true,
});
const observability = new ObservabilityStack(
  app,
  'ThreatForestObservability',
  {
    env: regionalEnvironment,
    foundation,
    agentCore,
    workflow: services.workflow,
    httpApiId: services.httpApi.apiId,
    webSocketApiId: services.webSocketApi.apiId,
    description: 'ThreatForest dashboards, alarms, and operational telemetry',
    terminationProtection: true,
  },
);

for (const stack of [
  foundation,
  identity,
  agentCore,
  services,
  waf,
  edge,
  edgeLogging,
  observability,
]) {
  Tags.of(stack).add('Application', 'ThreatForest');
  Tags.of(stack).add('Environment', DEPLOYMENT.environment);
  Tags.of(stack).add('ManagedBy', 'CDK');
}

app.synth();
