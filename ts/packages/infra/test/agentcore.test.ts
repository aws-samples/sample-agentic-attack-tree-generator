import assert from 'node:assert/strict';
import test from 'node:test';
import { App, Stack, aws_cognito as cognito } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import {
  AgentCoreStack,
  RUNTIME_DOCKER_EXCLUDES,
} from '../src/agentcore-stack.js';
import { FoundationStack } from '../src/foundation-stack.js';

function template(): Template {
  const app = new App();
  const env = { account: '123456789012', region: 'eu-west-2' };
  const foundation = new FoundationStack(app, 'Foundation', { env });
  const identity = new Stack(app, 'IdentityFixture', { env });
  const userPool = new cognito.UserPool(identity, 'UserPool');
  const userPoolClient = userPool.addClient('Client', {
    generateSecret: false,
  });
  const stack = new AgentCoreStack(app, 'AgentCore', {
    env,
    foundation,
    userPool,
    userPoolClient,
    runtimeImageTag: 'test-sha',
    mapperImageTag: 'mapper-test-sha',
  });
  return Template.fromStack(stack);
}

test('runtime Docker context retains nested TypeScript source trees', () => {
  const excludes: readonly string[] = RUNTIME_DOCKER_EXCLUDES;
  assert.ok(!excludes.includes('src'));
  assert.ok(!excludes.includes('**/src'));
  assert.ok(excludes.includes('ts/packages/deployed-tests'));
  assert.ok(excludes.includes('ts/packages/hosted-api'));
  assert.ok(excludes.includes('ts/packages/infra'));
  assert.ok(excludes.includes('**/dist'));
});

test('runtime uses IAM invocation, VPC isolation, tracing, and bounded sessions', () => {
  const value = template();
  value.resourceCountIs('AWS::BedrockAgentCore::Runtime', 1);
  value.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
    LifecycleConfiguration: {
      IdleRuntimeSessionTimeout: 1800,
      MaxLifetime: 28800,
    },
    NetworkConfiguration: Match.objectLike({
      NetworkMode: 'VPC',
      NetworkModeConfig: Match.anyValue(),
    }),
    ProtocolConfiguration: 'HTTP',
  });
  value.resourceCountIs('AWS::Logs::Delivery', 5);
  value.resourceCountIs('AWS::Lambda::Function', 16);
  value.hasResourceProperties('AWS::Lambda::Function', {
    Code: {
      ZipFile: Match.stringLikeRegexp('requireMMDSV2'),
    },
    Runtime: 'python3.13',
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Code: {
      ZipFile: Match.stringLikeRegexp('associate_kms_key'),
    },
    Runtime: 'python3.13',
    Timeout: 300,
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Code: {
      ZipFile: Match.stringLikeRegexp(
        '/aws/bedrock-agentcore/runtimes/',
      ),
    },
    Runtime: 'python3.13',
    Timeout: 300,
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Code: {
      ZipFile: Match.stringLikeRegexp(
        'Timed out waiting for the AWS-managed shared spans log group',
      ),
    },
    Runtime: 'python3.13',
    Timeout: 300,
  });
  value.hasResourceProperties('AWS::CloudFormation::CustomResource', {
    LogGroupName: 'aws/spans',
    KmsKeyArn: Match.anyValue(),
    RetentionDays: 365,
  });
  value.hasResourceProperties('AWS::CloudFormation::CustomResource', {
    LogGroupName: '/aws/application-signals/data',
    KmsKeyArn: Match.anyValue(),
    RetentionDays: 365,
  });
  value.hasResourceProperties('AWS::CloudFormation::CustomResource', {
    LogGroupName:
      '/aws/bedrock-agentcore/evaluations/batch-evaluations/results/default',
    KmsKeyArn: Match.anyValue(),
    RetentionDays: 365,
  });

  const runtime = Object.values(value.findResources('AWS::BedrockAgentCore::Runtime'))[0] as {
    Properties: {
      AgentRuntimeArtifact: unknown;
      AuthorizerConfiguration?: unknown;
      EnvironmentVariables: Record<string, string>;
      RequestHeaderConfiguration?: unknown;
    };
  };
  assert.equal(runtime.Properties.AuthorizerConfiguration, undefined);
  assert.equal(
    runtime.Properties.EnvironmentVariables.THREATFOREST_PRINCIPAL_MODE,
    'runtime_user_id',
  );
  assert.equal(
    runtime.Properties.EnvironmentVariables.AGENT_OBSERVABILITY_ENABLED,
    'true',
  );
  assert.equal(
    runtime.Properties.EnvironmentVariables
      .UNIFIED_TRACES_DESTINATION_ENABLED,
    'false',
  );
  assert.equal(
    runtime.Properties.EnvironmentVariables.OTEL_RESOURCE_ATTRIBUTES,
    undefined,
  );
  assert.equal(
    runtime.Properties.EnvironmentVariables.OTEL_PROPAGATORS,
    'baggage,xray,tracecontext',
  );
  assert.deepEqual(runtime.Properties.RequestHeaderConfiguration, {
    RequestHeaderAllowlist: [
      'X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserId',
    ],
  });
  const artifact = JSON.stringify(runtime.Properties.AgentRuntimeArtifact);
  assert.match(artifact, /test-sha/);
});

test('memory is KMS encrypted and separates compact context from approved feedback', () => {
  const value = template();
  value.resourceCountIs('AWS::BedrockAgentCore::Memory', 1);
  const memory = Object.values(
    value.findResources('AWS::BedrockAgentCore::Memory'),
  )[0] as {
    DeletionPolicy: string;
    UpdateReplacePolicy: string;
  };
  assert.equal(memory.DeletionPolicy, 'RetainExceptOnCreate');
  assert.equal(memory.UpdateReplacePolicy, 'Retain');
  value.hasResourceProperties('AWS::BedrockAgentCore::Memory', {
    EncryptionKeyArn: Match.anyValue(),
    EventExpiryDuration: 365,
    MemoryStrategies: Match.arrayWith([
      Match.objectLike({
        SummaryMemoryStrategy: Match.objectLike({
          Namespaces: [
            '/threatforest/{actorId}/summaries/{sessionId}',
          ],
        }),
      }),
      Match.objectLike({
        SemanticMemoryStrategy: Match.objectLike({
          Namespaces: ['/threatforest/{actorId}/approved-feedback'],
        }),
      }),
    ]),
  });
  value.hasResourceProperties('AWS::BedrockAgentCore::ResourcePolicy', {
    ResourceArn: Match.anyValue(),
    Policy: Match.anyValue(),
  });
  assert.match(JSON.stringify(value.toJSON()), /RuntimeApplicationScopedMemory/);
  value.hasResourceProperties('AWS::Logs::DeliverySource', {
    LogType: 'APPLICATION_LOGS',
    ResourceArn: Match.anyValue(),
  });

  const policies = Object.values(
    value.findResources('AWS::IAM::Policy'),
  ) as Array<{
    Properties: {
      PolicyDocument: {
        Statement: Array<{
          Sid?: string;
          Action: string | string[];
          Resource: unknown;
          Condition?: unknown;
        }>;
      };
      Roles?: unknown[];
    };
  }>;
  const runtimePolicy = policies.find(({ Properties }) =>
    JSON.stringify(Properties.Roles).includes('RuntimeExecutionRole'),
  );
  assert.ok(runtimePolicy);
  const memoryKmsGrant = runtimePolicy.Properties.PolicyDocument.Statement.find(
    ({ Sid }) => Sid === 'UseAgentCoreMemoryEncryptionKey',
  );
  assert.ok(memoryKmsGrant);
  assert.deepEqual(memoryKmsGrant.Action, [
    'kms:CreateGrant',
    'kms:Decrypt',
    'kms:DescribeKey',
    'kms:GenerateDataKey',
    'kms:GenerateDataKeyWithoutPlaintext',
    'kms:ReEncrypt*',
  ]);
  assert.match(JSON.stringify(memoryKmsGrant.Resource), /MemoryKey/);
  const memoryKmsCondition = JSON.stringify(memoryKmsGrant.Condition);
  assert.match(memoryKmsCondition, /bedrock-agentcore\.eu-west-2\./);
  assert.match(memoryKmsCondition, /AWS::URLSuffix/);
});

test('gateway uses Cognito JWT, KMS, MCP, and enforced tenant policies', () => {
  const value = template();
  value.resourceCountIs('AWS::BedrockAgentCore::PolicyEngine', 1);
  const policyEngine = Object.values(
    value.findResources('AWS::BedrockAgentCore::PolicyEngine'),
  )[0] as {
    DeletionPolicy: string;
    UpdateReplacePolicy: string;
  };
  assert.equal(policyEngine.DeletionPolicy, 'RetainExceptOnCreate');
  assert.equal(policyEngine.UpdateReplacePolicy, 'Retain');
  value.hasResourceProperties('AWS::BedrockAgentCore::PolicyEngine', {
    EncryptionKeyArn: Match.anyValue(),
    Name: 'ThreatForestPolicyEngine',
  });
  value.resourceCountIs('AWS::BedrockAgentCore::Gateway', 1);
  value.hasResourceProperties('AWS::BedrockAgentCore::Gateway', {
    AuthorizerType: 'CUSTOM_JWT',
    KmsKeyArn: Match.anyValue(),
    PolicyEngineConfiguration: {
      Arn: Match.anyValue(),
      Mode: 'ENFORCE',
    },
    ProtocolType: 'MCP',
    ProtocolConfiguration: {
      Mcp: Match.objectLike({
        SearchType: 'SEMANTIC',
        SupportedVersions: ['2025-06-18', '2025-03-26'],
      }),
    },
  });
  value.resourceCountIs('AWS::BedrockAgentCore::GatewayTarget', 0);
  value.hasResourceProperties('AWS::IAM::Role', {
    AssumeRolePolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Condition: {
            ArnLike: {
              'aws:SourceArn': Match.anyValue(),
            },
            StringEquals: {
              'aws:SourceAccount': '123456789012',
            },
          },
          Principal: {
            Service: 'bedrock-agentcore.amazonaws.com',
          },
        }),
      ]),
    },
    Policies: Match.arrayWith([
      Match.objectLike({
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'ReadThreatForestPolicyEngine',
              Action: 'bedrock-agentcore:GetPolicyEngine',
            }),
          ]),
        },
      }),
    ]),
  });
  assert.match(
    JSON.stringify(value.toJSON()),
    /gateway\/threatforest-test-gateway/,
  );
  assert.match(JSON.stringify(value.toJSON()), /EncryptGatewayData/);
  assert.match(JSON.stringify(value.toJSON()), /EvaluateThreatForestPolicies/);
  assert.match(
    JSON.stringify(value.toJSON()),
    /GatewayPolicyEngine.*gateway\/threatforest-test-gateway-/,
  );

  const policies = Object.values(value.findResources('AWS::IAM::Policy')) as Array<{
    Properties: {
      PolicyDocument: {
        Statement: Array<{
          Sid?: string;
          Action: string | string[];
          Resource: unknown;
        }>;
      };
    };
  }>;
  const statements = policies.flatMap(
    ({ Properties }) => Properties.PolicyDocument.Statement,
  );
  const invoke = statements.find(({ Sid }) => Sid === 'InvokeConfiguredModels');
  const discover = statements.find(({ Sid }) => Sid === 'DiscoverConfiguredModels');
  assert.ok(invoke);
  assert.ok(discover);
  assert.notEqual(invoke.Resource, '*');
  assert.equal(discover.Resource, '*');
  assert.match(JSON.stringify(value.toJSON()), /bedrock-agentcore:AuthorizeAction/);
  assert.doesNotMatch(
    JSON.stringify(policies),
    /Sid":"InvokeAgentRuntime"/,
  );
});

test('completed runs are fully sampled by AgentCore online evaluation', () => {
  const value = template();
  value.resourceCountIs('AWS::XRay::TransactionSearchConfig', 0);
  value.hasResourceProperties('Custom::AWS', {
    Create: Match.serializedJson(
      Match.objectLike({
        service: 'XRay',
        action: 'updateTraceSegmentDestination',
        parameters: {
          Destination: 'CloudWatchLogs',
        },
        ignoreErrorCodesMatching: 'InvalidRequestException',
      }),
    ),
  });
  value.hasResourceProperties('Custom::AWS', {
    Update: Match.serializedJson(
      Match.objectLike({
        service: 'XRay',
        action: 'updateTraceSegmentDestination',
        parameters: {
          Destination: 'CloudWatchLogs',
        },
        ignoreErrorCodesMatching: 'InvalidRequestException',
      }),
    ),
  });
  value.resourceCountIs('AWS::BedrockAgentCore::Evaluator', 1);
  value.resourceCountIs('AWS::BedrockAgentCore::OnlineEvaluationConfig', 1);
  value.hasResourceProperties('AWS::BedrockAgentCore::Evaluator', {
    EvaluatorName: 'ThreatForestDomainQuality',
    Level: 'SESSION',
    EvaluatorConfig: {
      LlmAsAJudge: Match.objectLike({
        ModelConfig: {
          BedrockEvaluatorModelConfig: Match.objectLike({
            ModelId: 'global.anthropic.claude-sonnet-4-6',
            InferenceConfig: {
              MaxTokens: 512,
              Temperature: 0,
            },
          }),
        },
        Instructions: Match.stringLikeRegexp(
          'threatforest\\.run\\.output_quality',
        ),
      }),
    },
  });
  value.hasResourceProperties('AWS::BedrockAgentCore::OnlineEvaluationConfig', {
    OnlineEvaluationConfigName: 'ThreatForestEvaluation',
    DataSourceConfig: {
      CloudWatchLogs: Match.objectLike({
        LogGroupNames: Match.anyValue(),
        ServiceNames: Match.arrayWith(['ThreatForestRuntime.DEFAULT']),
      }),
    },
    Evaluators: Match.arrayEquals([
      { EvaluatorId: 'Builtin.ResponseRelevance' },
      { EvaluatorId: Match.anyValue() },
    ]),
    Rule: Match.objectLike({
      SamplingConfig: { SamplingPercentage: 100 },
      Filters: Match.arrayWith([
        {
          Key: 'name',
          Operator: 'Equals',
          Value: {
            StringValue: 'threatforest.run.output_quality',
          },
        },
      ]),
    }),
  });

  const evaluation = Object.values(
    value.findResources('AWS::BedrockAgentCore::OnlineEvaluationConfig'),
  )[0] as {
    Properties: {
      DataSourceConfig: {
        CloudWatchLogs: {
          LogGroupNames: unknown[];
        };
      };
    };
  };
  const evaluationLogGroups =
    evaluation.Properties.DataSourceConfig.CloudWatchLogs.LogGroupNames;
  assert.equal(evaluationLogGroups.length, 2);
  assert.equal(evaluationLogGroups[0], 'aws/spans');
  assert.match(JSON.stringify(evaluation.Properties.DataSourceConfig), /aws\/spans/);
  assert.match(
    JSON.stringify(evaluation.Properties.DataSourceConfig),
    /\/aws\/bedrock-agentcore\/runtimes\//,
  );
  const rendered = JSON.stringify(value.toJSON());
  assert.match(rendered, /EvaluationLogEncryption/);
  assert.match(rendered, /RuntimeLogEncryption/);
  assert.match(rendered, /SharedSpansLogEncryption/);
  assert.match(rendered, /ApplicationSignalsLogEncryption/);
  assert.match(rendered, /BatchEvaluationLogEncryption/);
  assert.match(rendered, /xray\.amazonaws\.com/);
  assert.match(rendered, /logs:PutLogEvents/);
  assert.match(rendered, /logs:AssociateKmsKey/);
  assert.match(rendered, /logs:PutRetentionPolicy/);
  const resources = value.toJSON().Resources;
  const transactionSearchId = Object.keys(resources).find(
    (id) => id.startsWith('TransactionSearch') && resources[id].Type === 'Custom::AWS',
  )!;
  assert.ok(transactionSearchId);
  const spansId = Object.keys(resources).find((id) => id.startsWith('SharedSpansLogEncryption'))!;
  const signalsId = Object.keys(resources).find((id) => id.startsWith('ApplicationSignalsLogEncryption'))!;
  assert.ok(resources[spansId].DependsOn.includes(transactionSearchId));
  assert.ok(resources[signalsId].DependsOn.includes(transactionSearchId));
  assert.ok(!resources[transactionSearchId].DependsOn.includes(spansId));
  const evaluationId = Object.keys(resources).find(
    (id) => resources[id].Type === 'AWS::BedrockAgentCore::OnlineEvaluationConfig',
  )!;
  assert.ok(resources[evaluationId].DependsOn.includes(spansId));
  assert.ok(resources[evaluationId].DependsOn.includes(signalsId));
  const tracePolicy = Object.entries(resources).find(
    ([id]) => id.startsWith('TransactionSearchLogPolicy'),
  )![1];
  assert.match(JSON.stringify(tracePolicy), /:xray:eu-west-2:/);
  const transactionSetupPolicy = Object.entries(resources).find(
    ([id]) => id.startsWith('AWS679f53fac002430cb0da5b7982bd2287ServiceRoleDefaultPolicy'),
  )![1];
  const setupPermissions = JSON.stringify(transactionSetupPolicy);
  assert.match(setupPermissions, /application-signals:StartDiscovery/);
  assert.match(setupPermissions, /iam:CreateServiceLinkedRole/);
  assert.match(setupPermissions, /iam:GetRole/);
  assert.match(setupPermissions, /AWSServiceRoleForCloudWatchApplicationSignals/);
  assert.match(setupPermissions, /cloudtrail:CreateServiceLinkedChannel/);
  assert.match(setupPermissions, /aws-service-channel\/application-signals\/\*/);
  const sharedSpansPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.includes('SharedSpansLogOnEventServiceRoleDefaultPolicy'),
  );
  assert.equal(sharedSpansPolicies.length, 1);
  assert.doesNotMatch(
    JSON.stringify(sharedSpansPolicies[0]?.[1]),
    /logs:CreateLogGroup/,
  );
  assert.match(
    JSON.stringify(sharedSpansPolicies[0]?.[1]),
    /log-group:aws\/spans:\*/,
  );
  const applicationSignalsPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.includes('ApplicationSignalsLogOnEventServiceRoleDefaultPolicy'),
  );
  assert.equal(applicationSignalsPolicies.length, 1);
  assert.match(
    JSON.stringify(applicationSignalsPolicies[0]?.[1]),
    /log-group:\/aws\/application-signals\/data:\*/,
  );
  const batchEvaluationLogPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.includes('BatchEvaluationLogOnEventServiceRoleDefaultPolicy'),
  );
  assert.equal(batchEvaluationLogPolicies.length, 1);
  const batchEvaluationLogPolicy = JSON.stringify(
    batchEvaluationLogPolicies[0]?.[1],
  );
  assert.match(batchEvaluationLogPolicy, /logs:CreateLogGroup/);
  assert.match(
    batchEvaluationLogPolicy,
    /log-group:\/aws\/bedrock-agentcore\/evaluations\/batch-evaluations\/results\/default/,
  );
  const runtimeLogPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.includes('RuntimeLogOnEventServiceRoleDefaultPolicy'),
  );
  assert.equal(runtimeLogPolicies.length, 1);
  assert.match(
    JSON.stringify(runtimeLogPolicies[0]?.[1]),
    /log-group:\/aws\/bedrock-agentcore\/runtimes\/\*:\*/,
  );
  const evaluationLogPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.startsWith('EvaluationLogOnEventServiceRoleDefaultPolicy'),
  );
  assert.equal(evaluationLogPolicies.length, 1);
  assert.match(
    JSON.stringify(evaluationLogPolicies[0]?.[1]),
    /log-group:\/aws\/bedrock-agentcore\/evaluations\/results\/\*:\*/,
  );
  const onlineEvaluationPolicies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  ).filter(([logicalId]) =>
    logicalId.includes('OnlineEvaluationExecutionRoleDefaultPolicy'),
  );
  assert.equal(onlineEvaluationPolicies.length, 1);
  const onlineEvaluationPolicy = JSON.stringify(
    onlineEvaluationPolicies[0]?.[1],
  );
  assert.match(onlineEvaluationPolicy, /kms:Decrypt/);
  assert.match(onlineEvaluationPolicy, /TelemetryKey/);
  assert.match(onlineEvaluationPolicy, /log-group:aws\/spans/);
  assert.match(
    onlineEvaluationPolicy,
    /log-group:\/aws\/bedrock-agentcore\/runtimes\//,
  );
  assert.match(
    rendered,
    /\/aws\/bedrock-agentcore\/evaluations\/results\/\*/,
  );
  assert.match(
    rendered,
    /\/aws\/bedrock-agentcore\/evaluations\/batch-evaluations\/results\/default/,
  );
  assert.match(
    rendered,
    /\/aws\/bedrock-agentcore\/runtimes\/\*/,
  );
});
