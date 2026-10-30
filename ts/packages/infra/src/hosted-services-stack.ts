import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import {
  CfnOutput,
  Duration,
  ArnFormat,
  Size,
  Stack,
  type StackProps,
  aws_apigatewayv2 as apigatewayv2,
  aws_apigatewayv2_authorizers as authorizers,
  aws_apigatewayv2_integrations as integrations,
  aws_bedrockagentcore as agentcore,
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_kms as kms,
  aws_lambda as lambda,
  aws_lambda_event_sources as eventSources,
  aws_lambda_nodejs as nodejs,
  aws_pipes as pipes,
  aws_sqs as sqs,
  aws_stepfunctions as stepfunctions,
  aws_stepfunctions_tasks as tasks,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import type { AgentCoreStack } from './agentcore-stack.js';
import { DEPLOYMENT } from './config.js';
import type { FoundationStack } from './foundation-stack.js';
import type { IdentityStack } from './identity-stack.js';

const MCP_TARGET_NAME = 'ThreatForestTools';

export interface HostedServicesStackProps extends StackProps {
  readonly foundation: FoundationStack;
  readonly identity: IdentityStack;
  readonly agentCore: AgentCoreStack;
}

function entry(relativePath: string): string {
  return fileURLToPath(new URL(relativePath, import.meta.url));
}

function apiDomain(apiId: string, stack: Stack): string {
  return `${apiId}.execute-api.${stack.region}.${stack.urlSuffix}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mcpToolDefinitions(): agentcore.CfnGatewayTarget.ToolDefinitionProperty[] {
  const schemaPath = entry('../../hosted-api/mcp-tools.json');
  const parsed: unknown = JSON.parse(readFileSync(schemaPath, 'utf8'));
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('ThreatForest MCP tool schema must be a non-empty array');
  }

  const readOnlyTools = new Set([
    'list_applications',
    'get_application',
    'list_runs',
    'get_run',
    'list_pending_interactions',
  ]);
  const names = new Set<string>();
  for (const tool of parsed) {
    if (
      !isRecord(tool) ||
      typeof tool['name'] !== 'string' ||
      typeof tool['description'] !== 'string' ||
      !isRecord(tool['inputSchema']) ||
      tool['inputSchema']['type'] !== 'object' ||
      !isRecord(tool['inputSchema']['properties']) ||
      !Array.isArray(tool['inputSchema']['required']) ||
      !tool['inputSchema']['required'].every(
        (field): field is string => typeof field === 'string',
      )
    ) {
      throw new Error('ThreatForest MCP tool schema is malformed');
    }
    if (names.has(tool['name'])) {
      throw new Error(`Duplicate ThreatForest MCP tool: ${tool['name']}`);
    }
    names.add(tool['name']);
    if (
      !Object.hasOwn(tool['inputSchema']['properties'], 'owner_id') ||
      !tool['inputSchema']['required'].includes('owner_id')
    ) {
      throw new Error(
        `ThreatForest MCP tool ${tool['name']} must require owner_id`,
      );
    }
    if (
      !readOnlyTools.has(tool['name']) &&
      (!Object.hasOwn(
        tool['inputSchema']['properties'],
        'idempotency_key',
      ) ||
        !tool['inputSchema']['required'].includes('idempotency_key'))
    ) {
      throw new Error(
        `ThreatForest MCP mutation ${tool['name']} must require idempotency_key`,
      );
    }
  }

  return parsed as agentcore.CfnGatewayTarget.ToolDefinitionProperty[];
}

export class HostedServicesStack extends Stack {
  readonly httpApi: apigatewayv2.HttpApi;
  readonly webSocketApi: apigatewayv2.WebSocketApi;
  readonly webSocketStage: apigatewayv2.WebSocketStage;
  readonly workflow: stepfunctions.StateMachine;
  readonly httpFunction: lambda.Function;
  readonly mcpFunction: lambda.Function;
  readonly mcpTarget: agentcore.CfnGatewayTarget;
  readonly tenantPolicy: agentcore.CfnPolicy;
  readonly webSocketFunction: lambda.Function;
  readonly webSocketFanoutFunction: lambda.Function;
  readonly dispatchRelayFunction: lambda.Function;
  readonly ingestionFunction: lambda.Function;
  readonly reportImportFunction: lambda.Function;
  readonly dispatcherFunction: lambda.Function;
  readonly httpOriginDomain: string;
  readonly webSocketOriginDomain: string;

  constructor(scope: Construct, id: string, props: HostedServicesStackProps) {
    super(scope, id, props);

    const { foundation, identity, agentCore } = props;
    const workflowsKey = kms.Key.fromKeyArn(
      this,
      'WorkflowsKey',
      foundation.keys.workflows.keyArn,
    );
    const telemetryKey = kms.Key.fromKeyArn(
      this,
      'TelemetryKey',
      foundation.keys.telemetry.keyArn,
    );
    const ingestionQueue = sqs.Queue.fromQueueAttributes(
      this,
      'IngestionQueue',
      {
        queueArn: foundation.ingestionQueue.queueArn,
        queueUrl: foundation.ingestionQueue.queueUrl,
      },
    );
    const runCommandQueue = sqs.Queue.fromQueueAttributes(
      this,
      'RunCommandQueue',
      {
        queueArn: foundation.runCommandQueue.queueArn,
        queueUrl: foundation.runCommandQueue.queueUrl,
      },
    );
    const reportImportQueue = sqs.Queue.fromQueueAttributes(
      this,
      'ReportImportQueue',
      {
        queueArn: foundation.reportImportQueue.queueArn,
        queueUrl: foundation.reportImportQueue.queueUrl,
      },
    );
    const serviceSecurityGroup = new ec2.SecurityGroup(
      this,
      'ServiceSecurityGroup',
      {
        vpc: foundation.vpc,
        allowAllOutbound: true,
        description: 'Outbound access for hosted API and workflow Lambdas',
      },
    );
    const commonFunctionProps = {
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node22',
      },
      vpc: foundation.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [serviceSecurityGroup],
      environmentEncryption: workflowsKey,
      tracing: lambda.Tracing.ACTIVE,
    };

    this.httpFunction = new nodejs.NodejsFunction(this, 'HttpFunction', {
      ...commonFunctionProps,
      entry: entry('../../hosted-api/src/lambda/http.ts'),
      handler: 'handler',
      timeout: Duration.seconds(29),
      memorySize: 2048,
      logGroup: foundation.apiLogGroup,
    });
    this.webSocketFunction = new nodejs.NodejsFunction(
      this,
      'WebSocketFunction',
      {
        ...commonFunctionProps,
        entry: entry('../../hosted-api/src/lambda/websocket.ts'),
        handler: 'handler',
        timeout: Duration.seconds(29),
        memorySize: 2048,
        logGroup: foundation.webSocketLogGroup,
      },
    );
    this.mcpFunction = new nodejs.NodejsFunction(this, 'McpFunction', {
      ...commonFunctionProps,
      entry: entry('../../hosted-api/src/lambda/mcp-tools.ts'),
      handler: 'handler',
      timeout: Duration.seconds(29),
      memorySize: 2048,
      reservedConcurrentExecutions: 25,
      logGroup: foundation.mcpLogGroup,
      environment: {
        AGENTCORE_GATEWAY_ID: agentCore.gateway.gatewayId,
        CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
        INGESTION_QUEUE_URL: foundation.ingestionQueue.queueUrl,
      },
    });
    this.mcpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:BatchGetItem',
          'dynamodb:BatchWriteItem',
          'dynamodb:ConditionCheckItem',
          'dynamodb:DeleteItem',
          'dynamodb:DescribeTable',
          'dynamodb:GetItem',
          'dynamodb:PutItem',
          'dynamodb:Query',
          'dynamodb:Scan',
          'dynamodb:TransactGetItems',
          'dynamodb:TransactWriteItems',
          'dynamodb:UpdateItem',
        ],
        resources: [
          foundation.stateTable.tableArn,
          `${foundation.stateTable.tableArn}/index/*`,
        ],
      }),
    );
    this.mcpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Decrypt', 'kms:DescribeKey'],
        resources: [foundation.keys.state.keyArn],
      }),
    );
    new iam.Policy(this, 'GatewayMcpInvokePolicy', {
      roles: [agentCore.gateway.role],
      statements: [
        new iam.PolicyStatement({
          actions: ['lambda:InvokeFunction'],
          resources: [this.mcpFunction.functionArn],
        }),
      ],
    });
    const mcpTools = mcpToolDefinitions();
    const tenantActions = mcpTools.map(
      (tool) => `AgentCore::Action::"${MCP_TARGET_NAME}___${tool.name}"`,
    );
    this.mcpTarget = new agentcore.CfnGatewayTarget(
      this,
      'McpLambdaTarget',
      {
        gatewayIdentifier: agentCore.gateway.gatewayId,
        name: MCP_TARGET_NAME,
        description:
          'Tenant-scoped ThreatForest application, run, and HITL tools',
        credentialProviderConfigurations: [
          { credentialProviderType: 'GATEWAY_IAM_ROLE' },
        ],
        targetConfiguration: {
          mcp: {
            lambda: {
              lambdaArn: this.mcpFunction.functionArn,
              toolSchema: {
                inlinePayload: mcpTools,
              },
            },
          },
        },
      },
    );
    this.tenantPolicy = new agentcore.CfnPolicy(
      this,
      'TenantOwnershipPolicy',
      {
        policyEngineId: agentCore.policyEngine.attrPolicyEngineId,
        name: 'ThreatForestTenantOwnership',
        description:
          'Only permit tool calls whose owner_id matches the Cognito subject',
        definition: {
          cedar: {
            statement: [
              'permit(',
              '  principal is AgentCore::OAuthUser,',
              '  action in [',
              ...tenantActions.map(
                (action, index) =>
                  `    ${action}${index === tenantActions.length - 1 ? '' : ','}`,
              ),
              '  ],',
              `  resource == AgentCore::Gateway::"${agentCore.gateway.gatewayArn}"`,
              ')',
              'when {',
              '  principal.hasTag("sub") &&',
              '  context.input.owner_id == principal.getTag("sub")',
              '};',
            ].join('\n'),
          },
        },
        enforcementMode: 'ACTIVE',
        validationMode: 'FAIL_ON_ANY_FINDINGS',
      },
    );
    this.tenantPolicy.node.addDependency(this.mcpTarget);

    const webSocketIntegration = (route: string) =>
      new integrations.WebSocketLambdaIntegration(
        `WebSocket${route}Integration`,
        this.webSocketFunction,
      );
    this.webSocketApi = new apigatewayv2.WebSocketApi(this, 'WebSocketApi', {
      apiName: `${DEPLOYMENT.namePrefix}-websocket`,
      connectRouteOptions: { integration: webSocketIntegration('Connect') },
      disconnectRouteOptions: {
        integration: webSocketIntegration('Disconnect'),
      },
      defaultRouteOptions: { integration: webSocketIntegration('Default') },
    });
    this.webSocketStage = new apigatewayv2.WebSocketStage(
      this,
      'WebSocketStage',
      {
        webSocketApi: this.webSocketApi,
        stageName: 'hosted',
        autoDeploy: true,
      },
    );
    const cfnWebSocketStage = this.webSocketStage.node
      .defaultChild as apigatewayv2.CfnStage;
    cfnWebSocketStage.accessLogSettings = {
      destinationArn: foundation.webSocketLogGroup.logGroupArn,
      format: JSON.stringify({
        requestId: '$context.requestId',
        routeKey: '$context.routeKey',
        status: '$context.status',
        integrationError: '$context.integrationErrorMessage',
        ip: '$context.identity.sourceIp',
      }),
    };

    const jwtAuthorizer = new authorizers.HttpJwtAuthorizer(
      'CognitoAuthorizer',
      identity.issuerUrl,
      {
        jwtAudience: [identity.userPoolClient.userPoolClientId],
      },
    );
    this.httpApi = new apigatewayv2.HttpApi(this, 'HttpApi', {
      apiName: `${DEPLOYMENT.namePrefix}-http`,
      description: 'Authenticated ThreatForest hosted control plane',
      defaultAuthorizer: jwtAuthorizer,
      defaultIntegration: new integrations.HttpLambdaIntegration(
        'HttpIntegration',
        this.httpFunction,
      ),
      createDefaultStage: true,
    });
    const defaultStage = this.httpApi.defaultStage?.node
      .defaultChild as apigatewayv2.CfnStage | undefined;
    if (defaultStage) {
      defaultStage.accessLogSettings = {
        destinationArn: foundation.apiLogGroup.logGroupArn,
        format: JSON.stringify({
          requestId: '$context.requestId',
          routeKey: '$context.routeKey',
          status: '$context.status',
          responseLength: '$context.responseLength',
          integrationError: '$context.integrationErrorMessage',
          ip: '$context.identity.sourceIp',
        }),
      };
    }

    const httpEnvironment = {
      CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
      ARTIFACTS_BUCKET_NAME: foundation.artifactsBucket.bucketName,
      ARTIFACTS_KMS_KEY_ID: foundation.keys.artifacts.keyArn,
      RUN_QUEUE_URL: foundation.runCommandQueue.queueUrl,
      INGESTION_QUEUE_URL: foundation.ingestionQueue.queueUrl,
      REPORT_IMPORT_QUEUE_URL: foundation.reportImportQueue.queueUrl,
      ORIGIN_SECRET_ARN: foundation.originCredential.secretArn,
      REPLAY_TICKET_SECRET_ARN: foundation.replayTicketSecret.secretArn,
      THREATFOREST_MODEL_SECRET_PREFIX: `threatforest/${DEPLOYMENT.environment}/users`,
      MODEL_SECRETS_KMS_KEY_ID: foundation.keys.workflows.keyArn,
      WEBSOCKET_MANAGEMENT_ENDPOINT: this.webSocketStage.callbackUrl,
      COGNITO_ISSUER: identity.issuerUrl,
      COGNITO_AUDIENCE: identity.userPoolClient.userPoolClientId,
      ALLOW_UNTICKETED_WEBSOCKET: 'false',
      AGENTCORE_SPANS_LOG_GROUP: 'aws/spans',
    };
    const webSocketEnvironment = {
      CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
      ORIGIN_SECRET_ARN: foundation.originCredential.secretArn,
      REPLAY_TICKET_SECRET_ARN: foundation.replayTicketSecret.secretArn,
      WEBSOCKET_MANAGEMENT_ENDPOINT: this.webSocketStage.callbackUrl,
      COGNITO_ISSUER: identity.issuerUrl,
      COGNITO_AUDIENCE: identity.userPoolClient.userPoolClientId,
      ALLOW_UNTICKETED_WEBSOCKET: 'false',
    };
    for (const [name, value] of Object.entries(httpEnvironment)) {
      this.httpFunction.addEnvironment(name, value);
    }
    for (const [name, value] of Object.entries(webSocketEnvironment)) {
      this.webSocketFunction.addEnvironment(name, value);
    }
    for (const function_ of [this.httpFunction, this.webSocketFunction]) {
      function_.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            'dynamodb:BatchGetItem',
            'dynamodb:BatchWriteItem',
            'dynamodb:DeleteItem',
            'dynamodb:DescribeTable',
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'dynamodb:Query',
            'dynamodb:Scan',
            'dynamodb:TransactGetItems',
            'dynamodb:TransactWriteItems',
            'dynamodb:UpdateItem',
          ],
          resources: [
            foundation.stateTable.tableArn,
            `${foundation.stateTable.tableArn}/index/*`,
          ],
        }),
      );
      function_.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:Decrypt', 'kms:DescribeKey'],
          resources: [foundation.keys.state.keyArn],
        }),
      );
      function_.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
          resources: [
            foundation.originCredential.secretArn,
            foundation.replayTicketSecret.secretArn,
          ],
        }),
      );
    }
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:ConditionCheckItem'],
        resources: [foundation.stateTable.tableArn],
      }),
    );
    this.webSocketFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:ConditionCheckItem'],
        resources: [foundation.stateTable.tableArn],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetBucketLocation', 's3:ListBucket'],
        resources: [foundation.artifactsBucket.bucketArn],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ManagePerUserModelCredentials',
        actions: [
          'secretsmanager:CreateSecret',
          'secretsmanager:DescribeSecret',
          'secretsmanager:PutSecretValue',
        ],
        resources: [
          this.formatArn({
            service: 'secretsmanager',
            resource: 'secret',
            resourceName: `threatforest/${DEPLOYMENT.environment}/users/*`,
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          }),
        ],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'EncryptPerUserModelCredentials',
        actions: [
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        resources: [foundation.keys.workflows.keyArn],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          's3:AbortMultipartUpload',
          's3:DeleteObject',
          's3:GetObject',
          's3:ListMultipartUploadParts',
          's3:PutObject',
        ],
        resources: [foundation.artifactsBucket.arnForObjects('*')],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        resources: [foundation.keys.artifacts.keyArn],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'bedrock:ListFoundationModels',
          'bedrock:ListInferenceProfiles',
        ],
        resources: ['*'],
      }),
    );
    this.httpFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'logs:DescribeLogStreams',
          'logs:FilterLogEvents',
          'logs:GetLogEvents',
        ],
        resources: [
          Stack.of(this).formatArn({
            service: 'logs',
            resource: 'log-group',
            resourceName: 'aws/spans:*',
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          }),
        ],
      }),
    );
    this.webSocketStage.grantManagementApiAccess(
      this.webSocketFunction,
    );
    this.webSocketFanoutFunction = new nodejs.NodejsFunction(
      this,
      'WebSocketFanoutFunction',
      {
        ...commonFunctionProps,
        entry: entry('../../hosted-api/src/lambda/websocket-fanout.ts'),
        handler: 'handler',
        timeout: Duration.minutes(2),
        memorySize: 2048,
        reservedConcurrentExecutions: 10,
        logGroup: foundation.webSocketFanoutLogGroup,
        environment: {
          CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
          WEBSOCKET_MANAGEMENT_ENDPOINT: this.webSocketStage.callbackUrl,
        },
      },
    );
    this.webSocketFanoutFunction.addEventSource(
      new eventSources.DynamoEventSource(foundation.stateTable, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 100,
        maxBatchingWindow: Duration.seconds(1),
        bisectBatchOnError: true,
        maxRecordAge: Duration.hours(23),
        retryAttempts: 10,
        parallelizationFactor: 1,
        reportBatchItemFailures: true,
        onFailure: new eventSources.SqsDlq(
          foundation.webSocketFanoutFailureQueue,
        ),
        filters: [
          {
            pattern: JSON.stringify({
              eventName: ['INSERT', 'MODIFY'],
              dynamodb: {
                NewImage: {
                  entity: {
                    S: ['event', 'hosted-websocket-subscription'],
                  },
                },
              },
            }),
          },
        ],
        filterEncryption: telemetryKey,
      }),
    );
    foundation.stateTable.grantReadWriteData(
      this.webSocketFanoutFunction,
    );
    this.webSocketStage.grantManagementApiAccess(
      this.webSocketFanoutFunction,
    );
    this.dispatchRelayFunction = new nodejs.NodejsFunction(
      this,
      'DispatchRelayFunction',
      {
        ...commonFunctionProps,
        entry: entry('../../hosted-api/src/lambda/dispatch-relay.ts'),
        handler: 'handler',
        timeout: Duration.minutes(2),
        memorySize: 1024,
        reservedConcurrentExecutions: 10,
        logGroup: foundation.dispatchRelayLogGroup,
        environment: {
          RUN_QUEUE_URL: foundation.runCommandQueue.queueUrl,
          INGESTION_QUEUE_URL: foundation.ingestionQueue.queueUrl,
          REPORT_IMPORT_QUEUE_URL: foundation.reportImportQueue.queueUrl,
        },
      },
    );
    this.dispatchRelayFunction.addEventSource(
      new eventSources.DynamoEventSource(foundation.stateTable, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 100,
        maxBatchingWindow: Duration.seconds(1),
        bisectBatchOnError: true,
        maxRecordAge: Duration.hours(23),
        retryAttempts: 10,
        parallelizationFactor: 1,
        reportBatchItemFailures: true,
        onFailure: new eventSources.SqsDlq(
          foundation.dispatchRelayFailureQueue,
        ),
        filters: [
          {
            pattern: JSON.stringify({
              eventName: ['INSERT', 'MODIFY'],
              dynamodb: {
                NewImage: {
                  entity: { S: ['outbox-event', 'upload_manifest'] },
                },
              },
            }),
          },
        ],
        filterEncryption: telemetryKey,
      }),
    );
    for (const queue of [
      foundation.runCommandQueue,
      foundation.ingestionQueue,
      foundation.reportImportQueue,
    ]) {
      queue.grantSendMessages(this.dispatchRelayFunction);
    }

    this.ingestionFunction = new nodejs.NodejsFunction(
      this,
      'IngestionFunction',
      {
        ...commonFunctionProps,
        entry: entry('../../ingestion/src/lambda/worker.ts'),
        handler: 'handler',
        timeout: Duration.minutes(15),
        memorySize: 4096,
        ephemeralStorageSize: Size.gibibytes(10),
        reservedConcurrentExecutions: 10,
        logGroup: foundation.ingestionLogGroup,
        environment: {
          INGESTION_BUCKET: foundation.artifactsBucket.bucketName,
          INGESTION_KMS_KEY_ID: foundation.keys.artifacts.keyArn,
          INGESTION_TABLE_NAME: foundation.stateTable.tableName,
          INGESTION_TEXTRACT_ENABLED: 'true',
          INGESTION_PROCESSING_LEASE_SECONDS: '1200',
        },
      },
    );
    this.ingestionFunction.addEventSource(
      new eventSources.SqsEventSource(ingestionQueue, {
        batchSize: 1,
        reportBatchItemFailures: true,
        maxConcurrency: 10,
      }),
    );
    workflowsKey.grantDecrypt(this.ingestionFunction);
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:BatchGetItem',
          'dynamodb:BatchWriteItem',
          'dynamodb:DeleteItem',
          'dynamodb:DescribeTable',
          'dynamodb:GetItem',
          'dynamodb:PutItem',
          'dynamodb:Query',
          'dynamodb:Scan',
          'dynamodb:TransactGetItems',
          'dynamodb:TransactWriteItems',
          'dynamodb:UpdateItem',
        ],
        resources: [
          foundation.stateTable.tableArn,
          `${foundation.stateTable.tableArn}/index/*`,
        ],
      }),
    );
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Decrypt', 'kms:DescribeKey'],
        resources: [foundation.keys.state.keyArn],
      }),
    );

    this.reportImportFunction = new nodejs.NodejsFunction(
      this,
      'ReportImportFunction',
      {
        ...commonFunctionProps,
        entry: entry(
          '../../hosted-api/src/lambda/report-import-worker.ts',
        ),
        handler: 'handler',
        timeout: Duration.minutes(15),
        memorySize: 4096,
        ephemeralStorageSize: Size.gibibytes(10),
        reservedConcurrentExecutions: 5,
        logGroup: foundation.reportImportLogGroup,
        environment: {
          CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
          ARTIFACTS_BUCKET_NAME: foundation.artifactsBucket.bucketName,
          ARTIFACTS_KMS_KEY_ID: foundation.keys.artifacts.keyArn,
        },
      },
    );
    this.reportImportFunction.addEventSource(
      new eventSources.SqsEventSource(reportImportQueue, {
        batchSize: 1,
        reportBatchItemFailures: true,
        maxConcurrency: 5,
      }),
    );
    workflowsKey.grantDecrypt(this.reportImportFunction);
    this.reportImportFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:GetItem',
          'dynamodb:PutItem',
          'dynamodb:Query',
          'dynamodb:UpdateItem',
        ],
        resources: [
          foundation.stateTable.tableArn,
          `${foundation.stateTable.tableArn}/index/*`,
        ],
      }),
    );
    this.reportImportFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetBucketLocation', 's3:ListBucket'],
        resources: [foundation.artifactsBucket.bucketArn],
      }),
    );
    this.reportImportFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetObject', 's3:PutObject'],
        resources: [foundation.artifactsBucket.arnForObjects('*')],
      }),
    );
    this.reportImportFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        resources: [foundation.keys.artifacts.keyArn],
      }),
    );
    this.reportImportFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Decrypt', 'kms:DescribeKey'],
        resources: [foundation.keys.state.keyArn],
      }),
    );
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetBucketLocation', 's3:ListBucket'],
        resources: [foundation.artifactsBucket.bucketArn],
      }),
    );
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          's3:AbortMultipartUpload',
          's3:DeleteObject',
          's3:GetObject',
          's3:ListMultipartUploadParts',
          's3:PutObject',
        ],
        resources: [foundation.artifactsBucket.arnForObjects('*')],
      }),
    );
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        resources: [foundation.keys.artifacts.keyArn],
      }),
    );
    this.ingestionFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'textract:StartDocumentTextDetection',
          'textract:GetDocumentTextDetection',
        ],
        resources: ['*'],
      }),
    );

    this.dispatcherFunction = new nodejs.NodejsFunction(
      this,
      'RunDispatcherFunction',
      {
        ...commonFunctionProps,
        entry: entry('../../hosted-api/src/lambda/run-dispatcher.ts'),
        handler: 'handler',
        timeout: Duration.minutes(15),
        memorySize: 1024,
        logGroup: foundation.workflowLogGroup,
        environment: {
          AGENTCORE_RUNTIME_ARN: agentCore.runtime.agentRuntimeArn,
          AGENTCORE_RUNTIME_QUALIFIER: 'DEFAULT',
          CONTROL_PLANE_TABLE_NAME: foundation.stateTable.tableName,
        },
      },
    );
    agentCore.runtime.grantInvoke(this.dispatcherFunction);
    this.dispatcherFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:GetItem'],
        resources: [foundation.stateTable.tableArn],
      }),
    );
    this.dispatcherFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Decrypt', 'kms:DescribeKey'],
        resources: [foundation.keys.state.keyArn],
      }),
    );

    const normalizeRunCommand = new stepfunctions.Pass(
      this,
      'NormalizeRunCommand',
      {
        parameters: {
          'body.$': '$[0].body',
        },
      },
    );
    const invokeRuntime = new tasks.LambdaInvoke(this, 'InvokeRuntime', {
      lambdaFunction: this.dispatcherFunction,
      payload: stepfunctions.TaskInput.fromObject({
        'body.$': '$.body',
      }),
      payloadResponseOnly: true,
      resultPath: '$.runtime',
    });
    invokeRuntime.addRetry({
      errors: [
        'Lambda.ServiceException',
        'Lambda.TooManyRequestsException',
        'RuntimeClientError',
      ],
      interval: Duration.seconds(10),
      backoffRate: 2,
      maxAttempts: 6,
    });
    const waitForRuntime = new stepfunctions.Wait(this, 'WaitForRuntime', {
      time: stepfunctions.WaitTime.duration(Duration.seconds(30)),
    });
    const runtimeBoundary = new stepfunctions.Choice(this, 'RuntimeBoundary')
      .when(
        stepfunctions.Condition.stringEquals('$.runtime.boundary', 'busy'),
        waitForRuntime.next(invokeRuntime),
      )
      .otherwise(new stepfunctions.Succeed(this, 'BoundaryReached'));
    this.workflow = new stepfunctions.StateMachine(this, 'RunWorkflow', {
      stateMachineName: `${DEPLOYMENT.namePrefix}-run`,
      definitionBody: stepfunctions.DefinitionBody.fromChainable(
        normalizeRunCommand
          .next(invokeRuntime)
          .next(runtimeBoundary),
      ),
      timeout: Duration.hours(8),
      tracingEnabled: true,
      encryptionConfiguration:
        new stepfunctions.CustomerManagedEncryptionConfiguration(
          workflowsKey,
          Duration.minutes(5),
        ),
      logs: {
        destination: foundation.workflowLogGroup,
        level: stepfunctions.LogLevel.ERROR,
        includeExecutionData: false,
      },
    });

    const pipeRole = new iam.Role(this, 'RunCommandPipeRole', {
      assumedBy: new iam.ServicePrincipal('pipes.amazonaws.com'),
      description: 'Moves encrypted run commands into durable Step Functions executions',
    });
    runCommandQueue.grantConsumeMessages(pipeRole);
    this.workflow.grantStartExecution(pipeRole);
    workflowsKey.grantEncryptDecrypt(pipeRole);
    telemetryKey.grantEncryptDecrypt(pipeRole);
    pipeRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [`${foundation.workflowLogGroup.logGroupArn}:*`],
      }),
    );
    new pipes.CfnPipe(this, 'RunCommandPipe', {
      name: `${DEPLOYMENT.namePrefix}-run-commands`,
      roleArn: pipeRole.roleArn,
      source: foundation.runCommandQueue.queueArn,
      target: this.workflow.stateMachineArn,
      desiredState: 'RUNNING',
      kmsKeyIdentifier: foundation.keys.workflows.keyArn,
      logConfiguration: {
        cloudwatchLogsLogDestination: {
          logGroupArn: foundation.workflowLogGroup.logGroupArn,
        },
        level: 'ERROR',
      },
      sourceParameters: {
        sqsQueueParameters: {
          batchSize: 1,
          maximumBatchingWindowInSeconds: 0,
        },
      },
      targetParameters: {
        inputTemplate: '{"body": <$.body>}',
        stepFunctionStateMachineParameters: {
          invocationType: 'FIRE_AND_FORGET',
        },
      },
    });

    new agentcore.CfnResourcePolicy(this, 'RuntimeInvocationPolicy', {
      resourceArn: agentCore.runtime.agentRuntimeArn,
      policy: this.toJsonString({
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'TrustedDispatcherOnly',
            Effect: 'Allow',
            Principal: {
              AWS: this.dispatcherFunction.role!.roleArn,
            },
            Action: [
              'bedrock-agentcore:InvokeAgentRuntime',
              'bedrock-agentcore:InvokeAgentRuntimeForUser',
            ],
            Resource: agentCore.runtime.agentRuntimeArn,
            Condition: {
              StringEquals: { 'aws:PrincipalAccount': this.account },
            },
          },
        ],
      }),
    });

    this.httpOriginDomain = apiDomain(this.httpApi.apiId, this);
    this.webSocketOriginDomain = apiDomain(this.webSocketApi.apiId, this);

    new CfnOutput(this, 'HttpApiEndpoint', {
      value: this.httpApi.apiEndpoint,
    });
    new CfnOutput(this, 'WebSocketUrl', {
      value: this.webSocketStage.url,
    });
    new CfnOutput(this, 'RunWorkflowArn', {
      value: this.workflow.stateMachineArn,
    });
  }
}
