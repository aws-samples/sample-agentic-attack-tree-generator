import test from 'node:test';
import { App, Stack, aws_cognito as cognito } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AgentCoreStack } from '../src/agentcore-stack.js';
import { FoundationStack } from '../src/foundation-stack.js';
import { ObservabilityStack } from '../src/observability-stack.js';

function template(): Template {
  const app = new App();
  const env = { account: '123456789012', region: 'eu-west-2' };
  const foundation = new FoundationStack(app, 'Foundation', { env });
  const identity = new Stack(app, 'IdentityFixture', { env });
  const userPool = new cognito.UserPool(identity, 'UserPool');
  const userPoolClient = userPool.addClient('Client', { generateSecret: false });
  const agentCore = new AgentCoreStack(app, 'AgentCore', {
    env,
    foundation,
    userPool,
    userPoolClient,
    runtimeImageTag: 'test',
    mapperImageTag: 'mapper-test',
  });
  const stack = new ObservabilityStack(app, 'Observability', {
    env,
    foundation,
    agentCore,
    httpApiId: 'http-api',
    webSocketApiId: 'ws-api',
  });
  return Template.fromStack(stack);
}

test('dashboard covers hosted services and alarm delivery is encrypted', () => {
  const value = template();
  value.resourceCountIs('AWS::CloudWatch::Dashboard', 1);
  value.hasResourceProperties('AWS::SNS::Topic', {
    KmsMasterKeyId: Match.anyValue(),
  });
  value.hasResourceProperties('AWS::CloudWatch::CompositeAlarm', {
    AlarmName: 'threatforest-test-service-health',
  });
  value.resourceCountIs('AWS::Logs::MetricFilter', 4);
  value.hasResourceProperties('AWS::CloudWatch::Alarm', {
    AlarmName: 'threatforest-test-dispatch-relay-failures',
  });
  value.hasResourceProperties('AWS::CloudWatch::Alarm', {
    AlarmName: 'threatforest-test-websocket-fanout-failures',
  });
  value.hasResourceProperties('AWS::CloudWatch::Alarm', {
    AlarmName: 'threatforest-test-delivery-failure-queues',
  });
  const serialized = JSON.stringify(value.toJSON());
  for (const expected of [
    'AWS/ApiGateway',
    'http-api',
    'ws-api',
    'ExportsOutputRefApiLogGroup',
    'ExportsOutputRefMcpLogGroup',
    'ExportsOutputRefWebSocketLogGroup',
    'ExportsOutputRefWebSocketFanoutLogGroup',
    'ExportsOutputRefDispatchRelayLogGroup',
    'ExportsOutputRefRuntimeLogGroup',
    'ExportsOutputRefIngestionLogGroup',
    'ExportsOutputRefMemoryLogGroup',
    'ExportsOutputRefGatewayLogGroup',
    'EvaluationLogEncryption',
  ]) {
    if (!serialized.includes(expected)) {
      throw new Error(`dashboard is missing ${expected}`);
    }
  }
});
