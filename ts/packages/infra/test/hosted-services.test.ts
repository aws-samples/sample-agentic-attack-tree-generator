import assert from 'node:assert/strict';
import test from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AgentCoreStack } from '../src/agentcore-stack.js';
import { FoundationStack } from '../src/foundation-stack.js';
import { HostedServicesStack } from '../src/hosted-services-stack.js';
import { IdentityStack } from '../src/identity-stack.js';

let cachedTemplate: Template | undefined;

function template(): Template {
  if (cachedTemplate) {
    return cachedTemplate;
  }
  const app = new App();
  const env = { account: '123456789012', region: 'eu-west-2' };
  const foundation = new FoundationStack(app, 'Foundation', { env });
  const identity = new IdentityStack(app, 'Identity', {
    env,
    callbackUrls: ['https://example.com/auth/callback'],
    logoutUrls: ['https://example.com/'],
  });
  const agentCore = new AgentCoreStack(app, 'AgentCore', {
    env,
    foundation,
    userPool: identity.userPool,
    userPoolClient: identity.userPoolClient,
    runtimeImageTag: 'test',
    mapperImageTag: 'mapper-test',
  });
  const stack = new HostedServicesStack(app, 'Services', {
    env,
    foundation,
    identity,
    agentCore,
  });
  cachedTemplate = Template.fromStack(stack);
  return cachedTemplate;
}

test('hosted APIs use Cognito JWT and signed-ticket WebSocket routing', () => {
  const value = template();
  value.resourceCountIs('AWS::ApiGatewayV2::Api', 2);
  value.resourceCountIs('AWS::ApiGatewayV2::Integration', 4);
  value.resourceCountIs('AWS::ApiGatewayV2::Authorizer', 1);
  value.hasResourceProperties('AWS::ApiGatewayV2::Authorizer', {
    AuthorizerType: 'JWT',
    IdentitySource: ['$request.header.Authorization'],
    JwtConfiguration: {
      Audience: Match.anyValue(),
      Issuer: Match.anyValue(),
    },
  });
  value.hasResourceProperties('AWS::ApiGatewayV2::Route', {
    AuthorizationType: 'JWT',
    AuthorizerId: Match.anyValue(),
    RouteKey: '$default',
  });
  for (const routeKey of ['$connect', '$disconnect', '$default']) {
    value.hasResourceProperties('AWS::ApiGatewayV2::Route', {
      AuthorizationType: 'NONE',
      RouteKey: routeKey,
    });
  }
  const permissions = Object.values(
    value.findResources('AWS::Lambda::Permission'),
  ) as Array<{
    Properties: {
      Action?: string;
      Principal?: string;
      SourceArn?: unknown;
    };
  }>;
  const webSocketPermissions = permissions.filter(
    ({ Properties }) =>
      Properties.Action === 'lambda:InvokeFunction' &&
      Properties.Principal === 'apigateway.amazonaws.com' &&
      JSON.stringify(Properties.SourceArn).includes('WebSocketApi'),
  );
  assert.equal(webSocketPermissions.length, 3);
  const permissionArns = JSON.stringify(
    webSocketPermissions.map(({ Properties }) => Properties.SourceArn),
  );
  assert.match(permissionArns, /\$connect/);
  assert.match(permissionArns, /\$disconnect/);
  assert.match(permissionArns, /\$default/);
  value.resourceCountIs('AWS::ApiGatewayV2::Stage', 2);
  value.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
    AccessLogSettings: {
      DestinationArn: Match.anyValue(),
      Format: Match.stringLikeRegexp('integrationError'),
    },
  });
});

test('hosted Lambdas are encrypted, traced, VPC attached, and ingestion is bounded', () => {
  const value = template();
  value.resourceCountIs('AWS::Lambda::Function', 8);
  const functions = Object.values(
    value.findResources('AWS::Lambda::Function'),
  ) as Array<{
    Properties: {
      Architectures?: string[];
      KmsKeyArn?: unknown;
      Runtime?: string;
      TracingConfig?: { Mode?: string };
      VpcConfig?: unknown;
    };
  }>;
  for (const function_ of functions) {
    assert.deepEqual(function_.Properties.Architectures, ['arm64']);
    assert.notEqual(function_.Properties.KmsKeyArn, undefined);
    assert.equal(function_.Properties.Runtime, 'nodejs22.x');
    assert.equal(function_.Properties.TracingConfig?.Mode, 'Active');
    assert.notEqual(function_.Properties.VpcConfig, undefined);
  }

  value.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({
        ALLOW_UNTICKETED_WEBSOCKET: 'false',
        ARTIFACTS_BUCKET_NAME: Match.anyValue(),
        ARTIFACTS_KMS_KEY_ID: Match.anyValue(),
        COGNITO_AUDIENCE: Match.anyValue(),
        COGNITO_ISSUER: Match.anyValue(),
        CONTROL_PLANE_TABLE_NAME: Match.anyValue(),
        INGESTION_QUEUE_URL: Match.anyValue(),
        ORIGIN_SECRET_ARN: Match.anyValue(),
        REPLAY_TICKET_SECRET_ARN: Match.anyValue(),
        RUN_QUEUE_URL: Match.anyValue(),
        WEBSOCKET_MANAGEMENT_ENDPOINT: Match.anyValue(),
      }),
    },
    MemorySize: 2048,
    Timeout: 29,
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({
        AGENTCORE_GATEWAY_ID: Match.anyValue(),
        CONTROL_PLANE_TABLE_NAME: Match.anyValue(),
        INGESTION_QUEUE_URL: Match.anyValue(),
      }),
    },
  });
  value.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({
        INGESTION_PROCESSING_LEASE_SECONDS: '1200',
        INGESTION_TEXTRACT_ENABLED: 'true',
      }),
    },
    EphemeralStorage: { Size: 10240 },
    MemorySize: 4096,
    ReservedConcurrentExecutions: 10,
    Timeout: 900,
  });
  value.hasResourceProperties('AWS::Lambda::EventSourceMapping', {
    BatchSize: 1,
    FunctionResponseTypes: ['ReportBatchItemFailures'],
    ScalingConfig: { MaximumConcurrency: 10 },
  });
  value.hasResourceProperties('AWS::Lambda::EventSourceMapping', {
    BatchSize: 100,
    BisectBatchOnFunctionError: true,
    FunctionResponseTypes: ['ReportBatchItemFailures'],
    MaximumBatchingWindowInSeconds: 1,
    MaximumRecordAgeInSeconds: 82800,
    ParallelizationFactor: 1,
    StartingPosition: 'LATEST',
  });
});

test('DynamoDB stream filters serialize valid Lambda event patterns', () => {
  const value = template();
  const mappings = Object.values(
    value.findResources('AWS::Lambda::EventSourceMapping'),
  ) as Array<{
    Properties: {
      FilterCriteria?: {
        Filters: Array<{ Pattern: string }>;
      };
    };
  }>;
  const patterns = mappings
    .flatMap(({ Properties }) => Properties.FilterCriteria?.Filters ?? [])
    .map(({ Pattern }) => JSON.parse(Pattern) as {
      eventName: string[];
      dynamodb: {
        NewImage: {
          entity: { S: string[] };
        };
      };
    });
  assert.equal(patterns.length, 2);
  for (const pattern of patterns) {
    assert.deepEqual(pattern.eventName, ['INSERT', 'MODIFY']);
  }
  assert.deepEqual(
    patterns.map(
      ({ dynamodb }) => dynamodb.NewImage.entity.S,
    ),
    [
      ['event', 'hosted-websocket-subscription'],
      ['outbox-event', 'upload_manifest'],
    ],
  );
});

test('MCP tools use a Lambda target with enforced Cognito tenant ownership', () => {
  const value = template();
  value.resourceCountIs('AWS::BedrockAgentCore::GatewayTarget', 1);
  value.hasResourceProperties('AWS::BedrockAgentCore::GatewayTarget', {
    CredentialProviderConfigurations: [
      {
        CredentialProviderType: 'GATEWAY_IAM_ROLE',
      },
    ],
    Name: 'ThreatForestTools',
    TargetConfiguration: {
      Mcp: {
        Lambda: {
          LambdaArn: Match.anyValue(),
          ToolSchema: {
            InlinePayload: Match.anyValue(),
          },
        },
      },
    },
  });
  value.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
    Definition: {
      Cedar: {
        Statement: Match.anyValue(),
      },
    },
    EnforcementMode: 'ACTIVE',
    Name: 'ThreatForestTenantOwnership',
    ValidationMode: 'FAIL_ON_ANY_FINDINGS',
  });
  const renderedTemplate = JSON.stringify(value.toJSON());
  assert.match(renderedTemplate, /principal is AgentCore::OAuthUser/);
  assert.match(renderedTemplate, /action in \[/);
  assert.match(
    renderedTemplate,
    /AgentCore::Action::\\"ThreatForestTools___list_applications\\"/,
  );
  assert.match(
    renderedTemplate,
    /AgentCore::Action::\\"ThreatForestTools___skip_interaction\\"/,
  );
  assert.doesNotMatch(
    renderedTemplate,
    /action in AgentCore::Action::\\"ThreatForestTools\\"/,
  );
  assert.match(renderedTemplate, /resource == AgentCore::Gateway/);
  assert.match(renderedTemplate, /context\.input\.owner_id == principal\.getTag/);
  assert.match(renderedTemplate, /AgentCore:ExportsOutput.*Gateway.*Arn/);
  value.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        AGENTCORE_GATEWAY_ID: Match.anyValue(),
        CONTROL_PLANE_TABLE_NAME: Match.anyValue(),
      },
    },
    MemorySize: 2048,
    ReservedConcurrentExecutions: 25,
    Runtime: 'nodejs22.x',
    Timeout: 29,
  });

  const target = Object.values(
    value.findResources('AWS::BedrockAgentCore::GatewayTarget'),
  )[0] as {
    Properties: {
      TargetConfiguration: {
        Mcp: {
          Lambda: {
            ToolSchema: {
              InlinePayload: Array<{
                Name: string;
                InputSchema: {
                  Properties: Record<string, unknown>;
                  Required: string[];
                };
              }>;
            };
          };
        };
      };
    };
  };
  const tools =
    target.Properties.TargetConfiguration.Mcp.Lambda.ToolSchema
      .InlinePayload;
  assert.ok(tools.length > 0);
  assert.equal(new Set(tools.map(({ Name }) => Name)).size, tools.length);
  for (const tool of tools) {
    assert.ok(Object.hasOwn(tool.InputSchema.Properties, 'owner_id'));
    assert.ok(tool.InputSchema.Required.includes('owner_id'));
  }

  const policies = JSON.stringify(
    value.findResources('AWS::IAM::Policy'),
  );
  assert.match(policies, /lambda:InvokeFunction/);
  assert.match(policies, /dynamodb:TransactWriteItems/);
  assert.doesNotMatch(
    JSON.stringify(
      value.findResources('AWS::Lambda::Function'),
    ),
    /AGENTCORE_TARGET_ID/,
  );
});

test('MCP and WebSocket handlers have workload-specific IAM boundaries', () => {
  const value = template();
  const policies = Object.entries(
    value.findResources('AWS::IAM::Policy'),
  );
  const policyFor = (roleFragment: string) => {
    const found = policies.find(([, resource]) =>
      JSON.stringify(resource).includes(roleFragment),
    );
    assert.ok(found, `IAM policy for ${roleFragment} was not found`);
    return JSON.stringify(found[1]);
  };
  const mcp = policyFor('McpFunctionServiceRole');
  assert.match(mcp, /dynamodb:TransactWriteItems/);
  assert.match(mcp, /dynamodb:ConditionCheckItem/);
  assert.match(mcp, /kms:Decrypt/);
  assert.match(mcp, /kms:DescribeKey/);
  for (const forbidden of [
    'bedrock:ListFoundationModels',
    'execute-api:ManageConnections',
    's3:GetObject',
    'secretsmanager:GetSecretValue',
    'sqs:SendMessage',
  ]) {
    assert.doesNotMatch(mcp, new RegExp(forbidden));
  }

  const http = policyFor('HttpFunctionServiceRole');
  assert.match(http, /dynamodb:TransactWriteItems/);
  assert.match(http, /dynamodb:ConditionCheckItem/);

  const websocket = policyFor('WebSocketFunctionServiceRole');
  assert.match(websocket, /dynamodb:TransactWriteItems/);
  assert.match(websocket, /dynamodb:ConditionCheckItem/);
  assert.match(websocket, /execute-api:ManageConnections/);
  assert.match(websocket, /secretsmanager:GetSecretValue/);
  for (const forbidden of [
    'bedrock:ListFoundationModels',
    's3:GetObject',
    'sqs:SendMessage',
  ]) {
    assert.doesNotMatch(websocket, new RegExp(forbidden));
  }

  const ingestion = policyFor('IngestionFunctionServiceRole');
  assert.match(ingestion, /dynamodb:TransactWriteItems/);
  assert.match(ingestion, /kms:Decrypt/);
  assert.match(ingestion, /StateKey/);

  const dispatcher = policyFor('RunDispatcherFunctionServiceRole');
  assert.match(dispatcher, /dynamodb:GetItem/);
  assert.match(dispatcher, /kms:Decrypt/);
  assert.match(dispatcher, /StateKey/);
});

test('HTTP configuration stores per-user provider credentials with the workflows key', () => {
  const value = template();
  const functions = value.findResources('AWS::Lambda::Function') as Record<
    string,
    { Properties?: { Environment?: { Variables?: Record<string, unknown> } } }
  >;
  const http = Object.values(functions).find(
    (resource) =>
      resource.Properties?.Environment?.Variables?.[
        'THREATFOREST_MODEL_SECRET_PREFIX'
      ] !== undefined,
  );
  assert.ok(http);
  assert.equal(
    http.Properties?.Environment?.Variables?.[
      'THREATFOREST_MODEL_SECRET_PREFIX'
    ],
    'threatforest/test/users',
  );
  assert.ok(
    http.Properties?.Environment?.Variables?.['MODEL_SECRETS_KMS_KEY_ID'],
  );

  const policies = JSON.stringify(value.findResources('AWS::IAM::Policy'));
  assert.match(policies, /secretsmanager:CreateSecret/);
  assert.match(policies, /secretsmanager:DescribeSecret/);
  assert.match(policies, /secretsmanager:PutSecretValue/);
  assert.match(policies, /ManagePerUserModelCredentials/);
  assert.match(policies, /EncryptPerUserModelCredentials/);
});

test('report import worker has the exact DynamoDB actions required by its store', () => {
  const policies = Object.values(
    template().findResources('AWS::IAM::Policy'),
  ) as Array<{
    Properties: {
      PolicyDocument: {
        Statement: Array<{
          Action: string | string[];
          Effect: string;
        }>;
      };
      Roles: unknown[];
    };
  }>;
  const policy = policies.find((candidate) =>
    JSON.stringify(candidate.Properties.Roles).includes(
      'ReportImportFunctionServiceRole',
    ),
  );
  assert.ok(policy, 'report import worker IAM policy was not found');
  const dynamoActions = policy.Properties.PolicyDocument.Statement.flatMap(
    (statement) => {
      const actions = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      return actions.filter((action) => action.startsWith('dynamodb:'));
    },
  ).sort();
  assert.deepEqual(dynamoActions, [
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:Query',
    'dynamodb:UpdateItem',
  ]);
});

test('run commands use encrypted durable orchestration and restricted Runtime invocation', () => {
  const value = template();
  value.hasResourceProperties('AWS::StepFunctions::StateMachine', {
    EncryptionConfiguration: {
      KmsDataKeyReusePeriodSeconds: 300,
      KmsKeyId: Match.anyValue(),
      Type: 'CUSTOMER_MANAGED_KMS_KEY',
    },
    LoggingConfiguration: {
      Destinations: Match.anyValue(),
      IncludeExecutionData: false,
      Level: 'ERROR',
    },
    StateMachineName: 'threatforest-test-run',
    TracingConfiguration: { Enabled: true },
  });
  const workflows = value.findResources(
    'AWS::StepFunctions::StateMachine',
  ) as Record<
    string,
    {
      Properties: {
        DefinitionString: {
          'Fn::Join': [string, Array<string | Record<string, unknown>>];
        };
      };
    }
  >;
  const workflow = Object.values(workflows)[0];
  assert.ok(workflow);
  const definition = workflow.Properties.DefinitionString['Fn::Join'][1]
    .filter((fragment): fragment is string => typeof fragment === 'string')
    .join('');
  assert.ok(
    definition.includes(
      '"NormalizeRunCommand":{"Type":"Pass","Parameters":' +
        '{"body.$":"$[0].body"},"Next":"InvokeRuntime"}',
    ),
  );
  assert.ok(
    definition.includes(
      '"Type":"Task","ResultPath":"$.runtime","Resource":"' +
        '","Parameters":{"body.$":"$.body"}}',
    ),
  );
  assert.match(definition, /"RuntimeClientError"/);
  assert.doesNotMatch(definition, /"RuntimeBusyError"/);
  assert.match(definition, /"Variable":"\$\.runtime\.boundary","StringEquals":"busy","Next":"WaitForRuntime"/);
  assert.match(definition, /"WaitForRuntime":\{"Type":"Wait","Seconds":30,"Next":"InvokeRuntime"\}/);
  assert.match(definition, /"Default":"BoundaryReached"/);
  assert.doesNotMatch(definition, /"ErrorEquals":\["Error"\]/);
  assert.doesNotMatch(definition, /"Parameters":"\$"/);
  value.hasResourceProperties('AWS::Pipes::Pipe', {
    DesiredState: 'RUNNING',
    KmsKeyIdentifier: Match.anyValue(),
    LogConfiguration: {
      CloudwatchLogsLogDestination: {
        LogGroupArn: Match.anyValue(),
      },
      Level: 'ERROR',
    },
    Source: Match.anyValue(),
    SourceParameters: {
      SqsQueueParameters: {
        BatchSize: 1,
        MaximumBatchingWindowInSeconds: 0,
      },
    },
    Target: Match.anyValue(),
    TargetParameters: {
      InputTemplate: '{"body": <$.body>}',
      StepFunctionStateMachineParameters: {
        InvocationType: 'FIRE_AND_FORGET',
      },
    },
  });
  value.hasResourceProperties('AWS::BedrockAgentCore::ResourcePolicy', {
    Policy: Match.anyValue(),
    ResourceArn: Match.anyValue(),
  });
  assert.match(
    JSON.stringify(
      value.findResources('AWS::BedrockAgentCore::ResourcePolicy'),
    ),
    /TrustedDispatcherOnly/,
  );
  assert.doesNotMatch(
    JSON.stringify(
      value.findResources('AWS::BedrockAgentCore::ResourcePolicy'),
    ),
    /TrustedGatewayOnly/,
  );

  const policies = JSON.stringify(
    value.findResources('AWS::IAM::Policy'),
  );
  for (const action of [
    'bedrock-agentcore:InvokeAgentRuntimeForUser',
    'dynamodb:TransactWriteItems',
    'kms:Decrypt',
    's3:PutObject',
    'secretsmanager:GetSecretValue',
    'sqs:SendMessage',
    'states:StartExecution',
    'textract:StartDocumentTextDetection',
  ]) {
    assert.match(policies, new RegExp(action));
  }
});
