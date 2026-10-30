import assert from 'node:assert/strict';
import test from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { FoundationStack } from '../src/foundation-stack.js';

function template(): Template {
  const app = new App();
  const stack = new FoundationStack(app, 'TestFoundation', {
    env: { account: '123456789012', region: 'eu-west-2' },
  });
  return Template.fromStack(stack);
}

test('foundation uses two AZs and a NAT gateway per AZ', () => {
  const value = template();
  value.resourceCountIs('AWS::EC2::NatGateway', 2);
  value.resourceCountIs('AWS::EC2::VPCEndpoint', 15);
  value.hasResourceProperties('AWS::ServiceDiscovery::PrivateDnsNamespace', {
    Name: 'threatforest-test.internal',
  });
  value.hasResourceProperties('AWS::EC2::FlowLog', {
    TrafficType: 'ALL',
  });
});

test('API Gateway has a regional CloudWatch log delivery role', () => {
  const value = template();
  value.hasResourceProperties('AWS::ApiGateway::Account', {
    CloudWatchRoleArn: Match.anyValue(),
  });
  value.hasResourceProperties('AWS::IAM::Role', {
    AssumeRolePolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Principal: { Service: 'apigateway.amazonaws.com' },
        }),
      ]),
    },
    ManagedPolicyArns: Match.anyValue(),
  });
  assert.match(
    JSON.stringify(value.toJSON()),
    /service-role\/AmazonAPIGatewayPushToCloudWatchLogs/,
  );
});

test('persisted data uses customer-managed KMS encryption and retention controls', () => {
  const value = template();
  value.resourceCountIs('AWS::KMS::Key', 8);
  value.hasResourceProperties('AWS::DynamoDB::Table', {
    BillingMode: 'PAY_PER_REQUEST',
    DeletionProtectionEnabled: true,
    PointInTimeRecoverySpecification: {
      PointInTimeRecoveryEnabled: true,
    },
    SSESpecification: {
      KMSMasterKeyId: Match.anyValue(),
      SSEEnabled: true,
      SSEType: 'KMS',
    },
  });
  value.hasResourceProperties('AWS::S3::Bucket', {
    BucketEncryption: {
      ServerSideEncryptionConfiguration: Match.arrayWith([
        Match.objectLike({
          ServerSideEncryptionByDefault: {
            SSEAlgorithm: 'aws:kms',
          },
        }),
      ]),
    },
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    },
    VersioningConfiguration: { Status: 'Enabled' },
  });
  value.hasResourceProperties('AWS::S3::BucketPolicy', {
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: 's3:PutObject',
          Effect: 'Deny',
          Sid: 'DenyUnencryptedArtifactWrites',
        }),
        Match.objectLike({
          Action: 's3:PutObject',
          Effect: 'Deny',
          Sid: 'DenyWrongArtifactKey',
        }),
      ]),
    },
  });
});

test('artifact CORS supports encrypted uploads and presigned report downloads', () => {
  const value = template();
  value.hasResourceProperties('AWS::S3::Bucket', {
    CorsConfiguration: {
      CorsRules: Match.arrayWith([
        Match.objectLike({
          AllowedMethods: Match.arrayWith(['GET', 'HEAD', 'PUT']),
          AllowedOrigins: ['*'],
          ExposedHeaders: Match.arrayWith([
            'Content-Disposition',
            'Content-Type',
            'x-amz-checksum-sha256',
          ]),
        }),
      ]),
    },
  });
});

test('container repositories are encrypted, immutable, and scan on push', () => {
  const value = template();
  value.resourceCountIs('AWS::ECR::Repository', 2);
  value.hasResourceProperties('AWS::ECR::Repository', {
    EncryptionConfiguration: {
      EncryptionType: 'KMS',
      KmsKey: Match.anyValue(),
    },
    ImageScanningConfiguration: { ScanOnPush: true },
    ImageTagMutability: 'IMMUTABLE',
  });
});

test('queues and log groups are encrypted with retained customer keys', () => {
  const value = template();
  value.resourceCountIs('AWS::SQS::Queue', 8);
  value.hasResourceProperties('AWS::SQS::Queue', {
    KmsMasterKeyId: Match.anyValue(),
  });
  value.hasResourceProperties('AWS::Logs::LogGroup', {
    KmsKeyId: Match.anyValue(),
    RetentionInDays: 365,
  });
  value.resourceCountIs('AWS::Logs::LogGroup', 13);
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
  value.hasResourceProperties('AWS::KMS::Key', {
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Sid: 'AllowAgentCoreBatchEvaluationEncryption',
          Principal: {
            Service: 'bedrock-agentcore.amazonaws.com',
          },
          Action: Match.arrayWith([
            'kms:GenerateDataKey',
            'kms:Decrypt',
          ]),
          Condition: {
            StringEquals: {
              'aws:SourceAccount': '123456789012',
            },
            ArnLike: {
              'aws:SourceArn': Match.anyValue(),
            },
          },
        }),
      ]),
    },
  });
  const rendered = JSON.stringify(value.toJSON());
  assert.match(
    rendered,
    /\/aws\/bedrock-agentcore\/evaluations\/results\/\*/,
  );
  assert.match(
    rendered,
    /\/aws\/bedrock-agentcore\/evaluations\/batch-evaluations\/results\/\*/,
  );
  assert.match(rendered, /\/aws\/bedrock-agentcore\/runtimes\/\*/);
  assert.match(rendered, /aws\/spans/);
  assert.match(rendered, /\/aws\/application-signals\/data/);
  value.hasResourceProperties('AWS::KMS::Key', {
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Sid: 'AllowLambdaFilterCriteriaDecryption',
          Principal: { Service: Match.anyValue() },
          Action: 'kms:Decrypt',
        }),
      ]),
    },
  });
  const renderedTemplate = JSON.stringify(value.toJSON());
  assert.match(renderedTemplate, /lambda\.eu-west-2/);
  assert.match(
    renderedTemplate,
    /bedrock-agentcore\.amazonaws\.com/,
  );
  assert.match(renderedTemplate, /batch-evaluate/);
  assert.match(renderedTemplate, /logs\.eu-west-2\./);
  assert.match(renderedTemplate, /log-group:\/threatforest\/test\/\*/);
  assert.match(
    renderedTemplate,
    /log-group:\/aws\/bedrock-agentcore\/evaluations\/results\/\*/,
  );
  assert.match(renderedTemplate, /log-group:aws\/spans/);
  assert.match(
    renderedTemplate,
    /log-group:\/aws\/application-signals\/data/,
  );

  const resources = value.toJSON().Resources as Record<
    string,
    { Type: string; DeletionPolicy?: string; UpdateReplacePolicy?: string }
  >;
  for (const resource of Object.values(resources).filter(
    ({ Type }) => Type === 'AWS::SQS::Queue' || Type === 'AWS::SecretsManager::Secret',
  )) {
    assert.equal(resource.DeletionPolicy, 'Retain');
    assert.equal(resource.UpdateReplacePolicy, 'Retain');
  }
});

test('origin and replay credentials are encrypted and retained', () => {
  const value = template();
  value.resourceCountIs('AWS::SecretsManager::Secret', 2);
  value.hasResourceProperties('AWS::SecretsManager::Secret', {
    KmsKeyId: Match.anyValue(),
    GenerateSecretString: {
      ExcludePunctuation: true,
      PasswordLength: 64,
    },
  });
  assert.ok(Object.keys(value.toJSON().Resources).length > 0);
});
