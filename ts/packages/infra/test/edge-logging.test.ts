import assert from 'node:assert/strict';
import test from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { EdgeLoggingStack } from '../src/edge-logging-stack.js';

// Deliberately different from the original deployment: KMS must trust the
// destination stack's account, never a workstation's configured account.
const account = '123456789012';

function template(): Template {
  const app = new App();
  const stack = new EdgeLoggingStack(app, 'TestEdgeLogging', {
    env: { account, region: 'us-east-1' },
    distributionArn: `arn:aws:cloudfront::${account}:distribution/EXAMPLE`,
  });
  return Template.fromStack(stack);
}

test('CloudFront standard logging v2 is configured in us-east-1', () => {
  const value = template();
  value.resourceCountIs('AWS::KMS::Key', 1);
  value.hasResourceProperties('AWS::KMS::Key', {
    EnableKeyRotation: true,
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Sid: 'AllowCloudWatchLogsEncryption',
          Principal: {
            Service: 'logs.us-east-1.amazonaws.com',
          },
          Action: Match.arrayWith([
            'kms:Decrypt',
            'kms:GenerateDataKey*',
          ]),
          Condition: {
            ArnLike: {
              'kms:EncryptionContext:aws:logs:arn':
                `arn:aws:logs:us-east-1:${account}:log-group:/threatforest/test/cloudfront-access`,
            },
          },
        }),
      ]),
    },
  });
  value.hasResourceProperties('AWS::Logs::LogGroup', {
    LogGroupName: '/threatforest/test/cloudfront-access',
    KmsKeyId: Match.anyValue(),
    RetentionInDays: 365,
  });
  value.hasResource('AWS::KMS::Key', {
    DeletionPolicy: 'RetainExceptOnCreate',
    UpdateReplacePolicy: 'Retain',
  });
  value.hasResource('AWS::Logs::LogGroup', {
    DeletionPolicy: 'RetainExceptOnCreate',
    UpdateReplacePolicy: 'Retain',
  });
  value.resourceCountIs('AWS::Logs::ResourcePolicy', 1);
  const policies = value.findResources('AWS::Logs::ResourcePolicy');
  const [policyId, policy] = Object.entries(policies)[0]!;
  const renderedPolicy = JSON.stringify(policy);
  assert.match(renderedPolicy, /delivery\.logs\.amazonaws\.com/);
  assert.match(renderedPolicy, /logs:CreateLogStream/);
  assert.match(renderedPolicy, /logs:PutLogEvents/);
  assert.match(renderedPolicy, /aws:SourceAccount/);
  assert.match(renderedPolicy, new RegExp(account));
  assert.match(
    renderedPolicy,
    /cloudfront-access:log-stream:\\u002a|cloudfront-access:log-stream:\*/,
  );
  assert.doesNotMatch(renderedPolicy, /cloudfront-access:\*:log-stream/);
  value.resourceCountIs('AWS::Logs::DeliverySource', 1);
  value.resourceCountIs('AWS::Logs::DeliveryDestination', 1);
  value.resourceCountIs('AWS::Logs::Delivery', 1);
  value.hasResourceProperties('AWS::Logs::DeliverySource', {
    Name: 'threatforest-test-cloudfront',
    LogType: 'ACCESS_LOGS',
    ResourceArn: `arn:aws:cloudfront::${account}:distribution/EXAMPLE`,
  });
  value.hasResourceProperties('AWS::Logs::DeliveryDestination', {
    Name: 'threatforest-test-cloudfront',
    DestinationResourceArn: Match.anyValue(),
    OutputFormat: 'json',
  });
  const destinations = value.findResources('AWS::Logs::DeliveryDestination');
  const destination = Object.values(destinations)[0] as {
    DependsOn?: string[];
  };
  assert.ok(destination.DependsOn?.includes(policyId));
  value.hasResourceProperties('AWS::Logs::Delivery', {
    DeliveryDestinationArn: Match.anyValue(),
    DeliverySourceName: 'threatforest-test-cloudfront',
  });
});

test('access logs retain request metadata but exclude OAuth queries and cookies', () => {
  const deliveries = template().findResources('AWS::Logs::Delivery');
  const delivery = Object.values(deliveries)[0] as {
    Properties: { RecordFields: string[] };
  };

  assert.ok(delivery.Properties.RecordFields.includes('cs-uri-stem'));
  assert.ok(delivery.Properties.RecordFields.includes('cs(User-Agent)'));
  assert.ok(delivery.Properties.RecordFields.includes('x-edge-request-id'));
  assert.ok(!delivery.Properties.RecordFields.includes('cs-uri-query'));
  assert.ok(!delivery.Properties.RecordFields.includes('cs(Cookie)'));
});

test('stack rejects CloudFront delivery control-plane resources outside us-east-1', () => {
  const app = new App();
  assert.throws(
    () =>
      new EdgeLoggingStack(app, 'InvalidEdgeLogging', {
        env: { account, region: 'eu-west-2' },
        distributionArn: `arn:aws:cloudfront::${account}:distribution/EXAMPLE`,
      }),
    /must be configured in us-east-1/,
  );
});
