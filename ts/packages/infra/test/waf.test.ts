import test from 'node:test';
import assert from 'node:assert/strict';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { WafStack } from '../src/waf-stack.js';

function template(): Template {
  const app = new App();
  const stack = new WafStack(app, 'TestWaf', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

test('global web ACL enables managed rules and per-IP rate limiting', () => {
  const value = template();
  value.hasResourceProperties('AWS::WAFv2::WebACL', {
    Scope: 'CLOUDFRONT',
    DefaultAction: { Allow: {} },
    VisibilityConfig: {
      CloudWatchMetricsEnabled: true,
      SampledRequestsEnabled: false,
    },
  });

  const webAcl = Object.values(value.findResources('AWS::WAFv2::WebACL'))[0] as {
    Properties: {
      Rules: Array<{
        Name: string;
        Action?: { Block: Record<string, never> };
        Statement: {
          ManagedRuleGroupStatement?: { Name: string; VendorName: string };
          RateBasedStatement?: {
            AggregateKeyType: string;
            EvaluationWindowSec: number;
            Limit: number;
          };
        };
        VisibilityConfig: { SampledRequestsEnabled: boolean };
      }>;
    };
  };
  assert.equal(webAcl.Properties.Rules.length, 4);
  assert.ok(webAcl.Properties.Rules.every((rule) => !rule.VisibilityConfig.SampledRequestsEnabled));
  const managedGroups = webAcl.Properties.Rules.flatMap((rule) =>
    rule.Statement.ManagedRuleGroupStatement
      ? [rule.Statement.ManagedRuleGroupStatement.Name]
      : [],
  );
  assert.deepEqual(managedGroups.sort(), [
    'AWSManagedRulesAmazonIpReputationList',
    'AWSManagedRulesCommonRuleSet',
    'AWSManagedRulesKnownBadInputsRuleSet',
  ]);
  const rateRule = webAcl.Properties.Rules.find((rule) => rule.Name === 'PerIpRateLimit');
  assert.deepEqual(rateRule?.Action, { Block: {} });
  assert.deepEqual(rateRule?.Statement.RateBasedStatement, {
    AggregateKeyType: 'IP',
    EvaluationWindowSec: 300,
    Limit: 2000,
  });
});

test('WAF logs are encrypted, retained, filtered, and redact credentials', () => {
  const value = template();
  value.hasResourceProperties('AWS::Logs::LogGroup', {
    KmsKeyId: Match.anyValue(),
    RetentionInDays: 365,
  });
  value.hasResourceProperties('AWS::KMS::Key', {
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Sid: 'AllowCloudWatchLogsEncryption',
          Principal: { Service: Match.anyValue() },
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
  const renderedTemplate = JSON.stringify(value.toJSON());
  assert.match(renderedTemplate, /logs\.us-east-1\./);
  assert.match(renderedTemplate, /log-group:aws-waf-logs-threatforest-test-edge\*/);
  value.hasResourceProperties('AWS::WAFv2::LoggingConfiguration', {
    LogDestinationConfigs: [Match.anyValue()],
    LoggingFilter: {
      DefaultBehavior: 'DROP',
      Filters: [
        {
          Behavior: 'KEEP',
          Conditions: [{ ActionCondition: { Action: 'BLOCK' } }],
          Requirement: 'MEETS_ANY',
        },
      ],
    },
    RedactedFields: Match.arrayWith([
      { SingleHeader: { Name: 'authorization' } },
      { SingleHeader: { Name: 'cookie' } },
      { QueryString: {} },
    ]),
  });

  const resources = value.toJSON().Resources as Record<
    string,
    { Type: string; DeletionPolicy?: string; UpdateReplacePolicy?: string }
  >;
  const retained = Object.values(resources).filter(
    ({ Type }) => Type === 'AWS::KMS::Key' || Type === 'AWS::Logs::LogGroup',
  );
  assert.ok(retained.length >= 2);
  assert.ok(
    retained.every(
      (resource) => resource.DeletionPolicy === 'Retain' && resource.UpdateReplacePolicy === 'Retain',
    ),
  );
});

test('blocked requests emit a CloudWatch alarm', () => {
  const value = template();
  value.hasResourceProperties('AWS::CloudWatch::Alarm', {
    Namespace: 'AWS/WAFV2',
    MetricName: 'BlockedRequests',
    Statistic: 'Sum',
    Period: 300,
    Threshold: 100,
    EvaluationPeriods: 1,
    TreatMissingData: 'notBreaching',
  });
  const alarm = Object.values(value.findResources('AWS::CloudWatch::Alarm'))[0] as {
    Properties: { Dimensions: Array<{ Name: string; Value: string }> };
  };
  assert.deepEqual(
    Object.fromEntries(alarm.Properties.Dimensions.map(({ Name, Value }) => [Name, Value])),
    {
      Region: 'Global',
      Rule: 'ALL',
      WebACL: 'threatforest-test-edge',
    },
  );
});

test('CloudFront WAF stack rejects non-us-east-1 deployments', () => {
  const app = new App();
  assert.throws(
    () =>
      new WafStack(app, 'WrongRegion', {
        env: { account: '123456789012', region: 'eu-west-2' },
      }),
    /must deploy in us-east-1/,
  );
});
