import {
  Arn,
  ArnFormat,
  CfnOutput,
  CustomResource,
  Duration,
  IgnoreMode,
  RemovalPolicy,
  Stack,
  type StackProps,
  aws_bedrockagentcore as agentcore,
  aws_cognito as cognito,
  aws_ec2 as ec2,
  aws_ecr_assets as ecrAssets,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_stepfunctions as stepfunctions,
  custom_resources as customResources,
} from 'aws-cdk-lib';
import { fileURLToPath } from 'node:url';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';
import type { FoundationStack } from './foundation-stack.js';
import { TtpMapperService } from './ttp-mapper-service.js';

export interface AgentCoreStackProps extends StackProps {
  readonly foundation: FoundationStack;
  readonly userPool: cognito.IUserPool;
  readonly userPoolClient: cognito.IUserPoolClient;
  readonly runtimeImageTag?: string;
  readonly mapperImageTag?: string;
}

const RUNTIME_NAME = 'ThreatForestRuntime';
const SHARED_SPANS_LOG_GROUP = 'aws/spans';
const APPLICATION_SIGNALS_LOG_GROUP = '/aws/application-signals/data';
const BATCH_EVALUATION_LOG_GROUP =
  '/aws/bedrock-agentcore/evaluations/batch-evaluations/results/default';
export const RUNTIME_DOCKER_EXCLUDES = [
  '.git',
  'Config',
  'docs',
  'ts/node_modules',
  'ts/web',
  'ts/packages/cli',
  'ts/packages/deployed-tests',
  'ts/packages/hosted-api',
  'ts/packages/infra',
  'ts/packages/ingestion',
  'ts/packages/mcp-server',
  'ts/packages/server',
  'ts/packages/spike',
  '**/dist',
] as const;

function addVendedLogDelivery(
  scope: Construct,
  id: string,
  sourceArn: string,
  destination: logs.ILogGroup,
): void {
  const stack = Stack.of(scope);
  const policy = new logs.ResourcePolicy(scope, `${id}DeliveryPolicy`);
  policy.document.addStatements(
    new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('delivery.logs.amazonaws.com')],
      actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
      resources: [`${destination.logGroupArn}:log-stream:*`],
      conditions: {
        StringEquals: { 'aws:SourceAccount': stack.account },
        ArnLike: {
          'aws:SourceArn': stack.formatArn({
            service: 'logs',
            resource: '*',
          }),
        },
      },
    }),
  );
  const deliveryDestination = new logs.CfnDeliveryDestination(scope, `${id}LogDestination`, {
    name: `${DEPLOYMENT.namePrefix}-${id.toLowerCase()}`,
    deliveryDestinationType: 'CWL',
    destinationResourceArn: destination.logGroupArn,
  });
  deliveryDestination.node.addDependency(policy);
  const deliverySource = new logs.CfnDeliverySource(scope, `${id}LogSource`, {
    name: `${DEPLOYMENT.namePrefix}-${id.toLowerCase()}`,
    resourceArn: sourceArn,
    logType: 'APPLICATION_LOGS',
  });
  const delivery = new logs.CfnDelivery(scope, `${id}LogDelivery`, {
    deliveryDestinationArn: deliveryDestination.attrArn,
    deliverySourceName: deliverySource.deliverySourceRef.deliverySourceName,
  });
  delivery.node.addDependency(deliveryDestination);
  delivery.node.addDependency(deliverySource);
}

const MMDS_PROVIDER_CODE = `
import boto3

client = boto3.client("bedrock-agentcore-control")

def _runtime(runtime_id):
    return client.get_agent_runtime(agentRuntimeId=runtime_id)

def on_event(event, _context):
    props = event["ResourceProperties"]
    runtime_id = props["RuntimeId"]
    physical_id = "threatforest-mmdsv2-" + runtime_id
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id, "Data": {"Skipped": True}}

    current = _runtime(runtime_id)
    if current.get("metadataConfiguration", {}).get("requireMMDSV2") is not True:
        allowed = set(
            client.meta.service_model.operation_model("UpdateAgentRuntime")
            .input_shape.members.keys()
        )
        request = {
            key: value
            for key, value in current.items()
            if key in allowed and value is not None
        }
        request["agentRuntimeId"] = runtime_id
        request["metadataConfiguration"] = {"requireMMDSV2": True}
        client.update_agent_runtime(**request)
    return {"PhysicalResourceId": physical_id}

def is_complete(event, _context):
    if event.get("Data", {}).get("Skipped"):
        return {"IsComplete": True}
    runtime_id = event["ResourceProperties"]["RuntimeId"]
    current = _runtime(runtime_id)
    status = current.get("status", "UNKNOWN")
    if status in {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}:
        raise RuntimeError("AgentCore Runtime failed while enabling MMDSv2: " + status)
    ready = (
        status == "READY"
        and current.get("metadataConfiguration", {}).get("requireMMDSV2") is True
    )
    return {
        "IsComplete": ready,
        "Data": {"Version": str(current.get("agentRuntimeVersion", ""))},
    }
`.trim();

const EVALUATION_LOG_PROVIDER_CODE = `
import boto3
import time

agentcore = boto3.client("bedrock-agentcore-control")
logs = boto3.client("logs")

def on_event(event, _context):
    props = event["ResourceProperties"]
    config_id = props["EvaluationConfigId"]
    physical_id = "threatforest-evaluation-log-" + config_id
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id, "Data": {"Skipped": True}}

    for _attempt in range(24):
        try:
            current = agentcore.get_online_evaluation_config(
                onlineEvaluationConfigId=config_id
            )
            status = current.get("status", "UNKNOWN")
            if status in {"CREATE_FAILED", "UPDATE_FAILED"}:
                raise RuntimeError(
                    "AgentCore Online Evaluation failed before log encryption: "
                    + status
                )
            log_group_name = (
                current.get("outputConfig", {})
                .get("cloudWatchConfig", {})
                .get("logGroupName")
            )
            if status == "ACTIVE" and log_group_name:
                logs.associate_kms_key(
                    logGroupName=log_group_name,
                    kmsKeyId=props["KmsKeyArn"],
                )
                logs.put_retention_policy(
                    logGroupName=log_group_name,
                    retentionInDays=int(props["RetentionDays"]),
                )
                return {
                    "PhysicalResourceId": physical_id,
                    "Data": {"LogGroupName": log_group_name},
                }
        except (
            agentcore.exceptions.ResourceNotFoundException,
            logs.exceptions.ResourceNotFoundException,
        ):
            pass
        time.sleep(10)

    raise TimeoutError(
        "Timed out waiting for the AgentCore evaluation result log group"
    )
`.trim();

const RUNTIME_LOG_PROVIDER_CODE = `
import boto3
import time

logs = boto3.client("logs")

def on_event(event, _context):
    props = event["ResourceProperties"]
    runtime_id = props["RuntimeId"]
    log_group_name = (
        "/aws/bedrock-agentcore/runtimes/" + runtime_id + "-DEFAULT"
    )
    physical_id = "threatforest-runtime-log-" + runtime_id
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id, "Data": {"Skipped": True}}

    for _attempt in range(24):
        response = logs.describe_log_groups(
            logGroupNamePrefix=log_group_name,
            limit=1,
        )
        current = next(
            (
                group
                for group in response.get("logGroups", [])
                if group.get("logGroupName") == log_group_name
            ),
            None,
        )
        if current is not None:
            logs.associate_kms_key(
                logGroupName=log_group_name,
                kmsKeyId=props["KmsKeyArn"],
            )
            logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=int(props["RetentionDays"]),
            )
            return {
                "PhysicalResourceId": physical_id,
                "Data": {"LogGroupName": log_group_name},
            }
        time.sleep(10)

    raise TimeoutError(
        "Timed out waiting for the AgentCore runtime log group"
    )
`.trim();

const SHARED_SPANS_LOG_PROVIDER_CODE = `
import boto3
import time

logs = boto3.client("logs")

def on_event(event, _context):
    props = event["ResourceProperties"]
    log_group_name = props["LogGroupName"]
    physical_id = "threatforest-shared-log-" + log_group_name.replace("/", "-")
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id, "Data": {"Skipped": True}}

    for _attempt in range(24):
        response = logs.describe_log_groups(
            logGroupNamePrefix=log_group_name,
            limit=1,
        )
        current = next(
            (
                group
                for group in response.get("logGroups", [])
                if group.get("logGroupName") == log_group_name
            ),
            None,
        )
        if current is not None:
            logs.associate_kms_key(
                logGroupName=log_group_name,
                kmsKeyId=props["KmsKeyArn"],
            )
            logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=int(props["RetentionDays"]),
            )
            return {
                "PhysicalResourceId": physical_id,
                "Data": {"LogGroupName": log_group_name},
            }
        time.sleep(10)

    raise TimeoutError(
        "Timed out waiting for the AWS-managed shared spans log group"
    )
`.trim();

const MANAGED_LOG_GROUP_PROVIDER_CODE = `
import boto3

logs = boto3.client("logs")

def on_event(event, _context):
    props = event["ResourceProperties"]
    log_group_name = props["LogGroupName"]
    physical_id = "threatforest-managed-log-" + log_group_name.replace("/", "-")
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id, "Data": {"Skipped": True}}

    response = logs.describe_log_groups(
        logGroupNamePrefix=log_group_name,
        limit=1,
    )
    current = next(
        (
            group
            for group in response.get("logGroups", [])
            if group.get("logGroupName") == log_group_name
        ),
        None,
    )
    if current is None:
        try:
            logs.create_log_group(
                logGroupName=log_group_name,
                kmsKeyId=props["KmsKeyArn"],
            )
        except logs.exceptions.ResourceAlreadyExistsException:
            logs.associate_kms_key(
                logGroupName=log_group_name,
                kmsKeyId=props["KmsKeyArn"],
            )
    else:
        logs.associate_kms_key(
            logGroupName=log_group_name,
            kmsKeyId=props["KmsKeyArn"],
        )
    logs.put_retention_policy(
        logGroupName=log_group_name,
        retentionInDays=int(props["RetentionDays"]),
    )
    return {
        "PhysicalResourceId": physical_id,
        "Data": {"LogGroupName": log_group_name},
    }
`.trim();

function enforceMmdsV2(
  scope: Construct,
  runtime: agentcore.Runtime,
  foundation: FoundationStack,
): CustomResource {
  const common = {
    runtime: lambda.Runtime.PYTHON_3_13,
    code: lambda.Code.fromInline(MMDS_PROVIDER_CODE),
    timeout: Duration.minutes(5),
    logGroup: foundation.workflowLogGroup,
    environmentEncryption: foundation.keys.workflows,
  };
  const onEvent = new lambda.Function(scope, 'MmdsOnEvent', {
    ...common,
    handler: 'index.on_event',
  });
  const isComplete = new lambda.Function(scope, 'MmdsIsComplete', {
    ...common,
    handler: 'index.is_complete',
  });
  for (const fn of [onEvent, isComplete]) {
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'bedrock-agentcore:GetAgentRuntime',
          'bedrock-agentcore:UpdateAgentRuntime',
        ],
        resources: [runtime.agentRuntimeArn],
      }),
    );
  }
  const provider = new customResources.Provider(scope, 'MmdsProvider', {
    onEventHandler: onEvent,
    isCompleteHandler: isComplete,
    queryInterval: Duration.seconds(10),
    totalTimeout: Duration.minutes(30),
    logGroup: foundation.workflowLogGroup,
    providerFunctionEnvEncryption: foundation.keys.workflows,
    disableWaiterStateMachineLogging: false,
    waiterStateMachineLogOptions: {
      destination: foundation.workflowLogGroup,
      level: stepfunctions.LogLevel.ERROR,
      includeExecutionData: false,
    },
  });
  const resource = new CustomResource(scope, 'MmdsV2', {
    serviceToken: provider.serviceToken,
    properties: {
      RuntimeId: runtime.agentRuntimeId,
      DesiredConfiguration: 'requireMMDSV2=true',
    },
  });
  resource.node.addDependency(runtime);
  return resource;
}

function encryptEvaluationLogGroup(
  scope: Construct,
  evaluation: agentcore.OnlineEvaluationConfig,
  foundation: FoundationStack,
): CustomResource {
  const common = {
    runtime: lambda.Runtime.PYTHON_3_13,
    code: lambda.Code.fromInline(EVALUATION_LOG_PROVIDER_CODE),
    timeout: Duration.minutes(5),
    logGroup: foundation.workflowLogGroup,
    environmentEncryption: foundation.keys.workflows,
  };
  const onEvent = new lambda.Function(scope, 'EvaluationLogOnEvent', {
    ...common,
    handler: 'index.on_event',
  });
  const evaluationLogGroupArn = Stack.of(scope).formatArn({
    service: 'logs',
    resource: 'log-group',
    resourceName: '/aws/bedrock-agentcore/evaluations/results/*',
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
  });
  onEvent.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['bedrock-agentcore:GetOnlineEvaluationConfig'],
      resources: [evaluation.onlineEvaluationConfigArn],
    }),
  );
  onEvent.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:AssociateKmsKey', 'logs:PutRetentionPolicy'],
      resources: [`${evaluationLogGroupArn}:*`],
    }),
  );
  onEvent.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['kms:DescribeKey'],
      resources: [foundation.keys.telemetry.keyArn],
    }),
  );
  const provider = new customResources.Provider(
    scope,
    'EvaluationLogProvider',
    {
      onEventHandler: onEvent,
      logGroup: foundation.workflowLogGroup,
      providerFunctionEnvEncryption: foundation.keys.workflows,
    },
  );
  const resource = new CustomResource(scope, 'EvaluationLogEncryption', {
    serviceToken: provider.serviceToken,
    properties: {
      EvaluationConfigId: evaluation.onlineEvaluationConfigId,
      KmsKeyArn: foundation.keys.telemetry.keyArn,
      RetentionDays: 365,
      ConfigurationVersion: '1',
    },
  });
  resource.node.addDependency(evaluation);
  return resource;
}

function encryptRuntimeLogGroup(
  scope: Construct,
  runtime: agentcore.Runtime,
  foundation: FoundationStack,
): CustomResource {
  const handler = new lambda.Function(scope, 'RuntimeLogOnEvent', {
    runtime: lambda.Runtime.PYTHON_3_13,
    code: lambda.Code.fromInline(RUNTIME_LOG_PROVIDER_CODE),
    handler: 'index.on_event',
    timeout: Duration.minutes(5),
    logGroup: foundation.workflowLogGroup,
    environmentEncryption: foundation.keys.workflows,
  });
  const runtimeLogGroupArn = Stack.of(scope).formatArn({
    service: 'logs',
    resource: 'log-group',
    resourceName: '/aws/bedrock-agentcore/runtimes/*',
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
  });
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:DescribeLogGroups'],
      resources: ['*'],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:AssociateKmsKey', 'logs:PutRetentionPolicy'],
      resources: [`${runtimeLogGroupArn}:*`],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['kms:DescribeKey'],
      resources: [foundation.keys.telemetry.keyArn],
    }),
  );
  const provider = new customResources.Provider(scope, 'RuntimeLogProvider', {
    onEventHandler: handler,
    logGroup: foundation.workflowLogGroup,
    providerFunctionEnvEncryption: foundation.keys.workflows,
  });
  const resource = new CustomResource(scope, 'RuntimeLogEncryption', {
    serviceToken: provider.serviceToken,
    properties: {
      RuntimeId: runtime.agentRuntimeId,
      KmsKeyArn: foundation.keys.telemetry.keyArn,
      RetentionDays: 365,
      ConfigurationVersion: '1',
    },
  });
  resource.node.addDependency(runtime);
  return resource;
}

function ensureSharedTraceLogGroup(
  scope: Construct,
  foundation: FoundationStack,
  id: string,
  logGroupName: string,
): CustomResource {
  const handler = new lambda.Function(scope, `${id}OnEvent`, {
    runtime: lambda.Runtime.PYTHON_3_13,
    code: lambda.Code.fromInline(SHARED_SPANS_LOG_PROVIDER_CODE),
    handler: 'index.on_event',
    timeout: Duration.minutes(5),
    logGroup: foundation.workflowLogGroup,
    environmentEncryption: foundation.keys.workflows,
  });
  const spansLogGroupArn = Stack.of(scope).formatArn({
    service: 'logs',
    resource: 'log-group',
    resourceName: logGroupName,
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
  });
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:DescribeLogGroups'],
      resources: ['*'],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:AssociateKmsKey', 'logs:PutRetentionPolicy'],
      resources: [`${spansLogGroupArn}:*`],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['kms:DescribeKey'],
      resources: [foundation.keys.telemetry.keyArn],
    }),
  );
  const provider = new customResources.Provider(
    scope,
    `${id}Provider`,
    {
      onEventHandler: handler,
      logGroup: foundation.workflowLogGroup,
      providerFunctionEnvEncryption: foundation.keys.workflows,
    },
  );
  return new CustomResource(scope, `${id}Encryption`, {
    serviceToken: provider.serviceToken,
    properties: {
      LogGroupName: logGroupName,
      KmsKeyArn: foundation.keys.telemetry.keyArn,
      RetentionDays: 365,
      ConfigurationVersion: '1',
    },
  });
}

function ensureManagedLogGroup(
  scope: Construct,
  foundation: FoundationStack,
  id: string,
  logGroupName: string,
): CustomResource {
  const handler = new lambda.Function(scope, `${id}OnEvent`, {
    runtime: lambda.Runtime.PYTHON_3_13,
    code: lambda.Code.fromInline(MANAGED_LOG_GROUP_PROVIDER_CODE),
    handler: 'index.on_event',
    timeout: Duration.minutes(1),
    logGroup: foundation.workflowLogGroup,
    environmentEncryption: foundation.keys.workflows,
  });
  const logGroupArn = Stack.of(scope).formatArn({
    service: 'logs',
    resource: 'log-group',
    resourceName: logGroupName,
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
  });
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:DescribeLogGroups'],
      resources: ['*'],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:CreateLogGroup'],
      resources: [logGroupArn],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['logs:AssociateKmsKey', 'logs:PutRetentionPolicy'],
      resources: [`${logGroupArn}:*`],
    }),
  );
  handler.addToRolePolicy(
    new iam.PolicyStatement({
      actions: ['kms:DescribeKey'],
      resources: [foundation.keys.telemetry.keyArn],
    }),
  );
  const provider = new customResources.Provider(scope, `${id}Provider`, {
    onEventHandler: handler,
    logGroup: foundation.workflowLogGroup,
    providerFunctionEnvEncryption: foundation.keys.workflows,
  });
  return new CustomResource(scope, `${id}Encryption`, {
    serviceToken: provider.serviceToken,
    properties: {
      LogGroupName: logGroupName,
      KmsKeyArn: foundation.keys.telemetry.keyArn,
      RetentionDays: 365,
      ConfigurationVersion: '1',
    },
  });
}

export class AgentCoreStack extends Stack {
  readonly memory: agentcore.Memory;
  readonly runtime: agentcore.Runtime;
  readonly gateway: agentcore.Gateway;
  readonly policyEngine: agentcore.CfnPolicyEngine;
  readonly onlineEvaluation: agentcore.OnlineEvaluationConfig;
  readonly evaluationLogGroupName: string;
  readonly runtimeLogGroupName: string;
  readonly ttpMapper: TtpMapperService;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);

    const { foundation, userPool, userPoolClient } = props;
    const runtimeImageAsset =
      props.runtimeImageTag === undefined
        ? new ecrAssets.DockerImageAsset(this, 'RuntimeImage', {
            directory: fileURLToPath(
              new URL('../../../../', import.meta.url),
            ),
            file: 'ts/packages/hosted-runtime/Dockerfile',
            platform: ecrAssets.Platform.LINUX_ARM64,
            ignoreMode: IgnoreMode.GLOB,
            exclude: [...RUNTIME_DOCKER_EXCLUDES],
          })
        : null;
    const runtimeImageTag =
      props.runtimeImageTag ?? runtimeImageAsset!.imageTag;
    const runtimeImageRepository =
      runtimeImageAsset?.repository ?? foundation.runtimeRepository;

    this.memory = new agentcore.Memory(this, 'Memory', {
      memoryName: 'ThreatForestMemory',
      description: 'Application-scoped compact context and approved feedback',
      expirationDuration: Duration.days(365),
      kmsKey: foundation.keys.memory,
      memoryStrategies: [
        agentcore.MemoryStrategy.usingSummarization({
          strategyName: 'ThreatModelSummary',
          description: 'Compact approved context for a user and application',
          namespaces: [
            '/threatforest/{actorId}/summaries/{sessionId}',
          ],
        }),
        agentcore.MemoryStrategy.usingSemantic({
          strategyName: 'ApprovedFeedback',
          description: 'Approved corrections and dispositions only',
          namespaces: ['/threatforest/{actorId}/approved-feedback'],
        }),
      ],
      tags: {
        Application: 'ThreatForest',
        Environment: DEPLOYMENT.environment,
      },
    });
    const memoryResource = this.memory.node.findChild(
      'Memory',
    ) as agentcore.CfnMemory;
    memoryResource.applyRemovalPolicy(
      RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    );

    const runtimeSecurityGroup = new ec2.SecurityGroup(this, 'RuntimeSecurityGroup', {
      vpc: foundation.vpc,
      allowAllOutbound: true,
      description: 'Outbound access for ThreatForest AgentCore Runtime',
    });
    this.ttpMapper = new TtpMapperService(this, 'TtpMapper', {
      foundation,
      namespace: foundation.ttpMapperNamespace,
      runtimeSecurityGroup,
      imageTag: props.mapperImageTag,
    });

    this.runtime = new agentcore.Runtime(this, 'Runtime', {
      runtimeName: RUNTIME_NAME,
      description: 'Durable boundary executor for ThreatForest',
      agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromEcrRepository(
        runtimeImageRepository,
        runtimeImageTag,
      ),
      networkConfiguration: agentcore.RuntimeNetworkConfiguration.usingVpc(this, {
        vpc: foundation.vpc,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        securityGroups: [runtimeSecurityGroup],
      }),
      protocolConfiguration: agentcore.ProtocolType.HTTP,
      authorizerConfiguration:
        agentcore.RuntimeAuthorizerConfiguration.usingIAM(),
      requestHeaderConfiguration: {
        allowlistedHeaders: [
          'X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserId',
        ],
      },
      lifecycleConfiguration: {
        idleRuntimeSessionTimeout: Duration.minutes(30),
        // Match the workflow ceiling so a healthy stage can finish before the
        // platform replaces its process. Individual stages remain bounded.
        maxLifetime: Duration.hours(8),
      },
      environmentVariables: {
        AWS_REGION: DEPLOYMENT.region,
        AGENT_OBSERVABILITY_ENABLED: 'true',
        UNIFIED_TRACES_DESTINATION_ENABLED: 'false',
        OTEL_PROPAGATORS: 'baggage,xray,tracecontext',
        THREATFOREST_ENVIRONMENT: DEPLOYMENT.environment,
        THREATFOREST_STATE_TABLE: foundation.stateTable.tableName,
        THREATFOREST_ARTIFACT_BUCKET: foundation.artifactsBucket.bucketName,
        THREATFOREST_ARTIFACT_KMS_KEY_ARN:
          foundation.keys.artifacts.keyArn,
        THREATFOREST_MEMORY_ID: this.memory.memoryId,
        THREATFOREST_ACTOR_HMAC_KEY_ARN: foundation.keys.actorHmac.keyArn,
        THREATFOREST_MEMORY_WRITE_POLICY: 'approved_only',
        THREATFOREST_PRINCIPAL_MODE: 'runtime_user_id',
        THREATFOREST_MODEL_SECRET_PREFIX: `threatforest/${DEPLOYMENT.environment}/users`,
        TF_ML_URL: this.ttpMapper.url,
      },
      tracingEnabled: true,
      loggingConfigs: [
        {
          logType: agentcore.LogType.APPLICATION_LOGS,
          destination: agentcore.LoggingDestination.cloudWatchLogs(foundation.runtimeLogGroup),
        },
        {
          logType: agentcore.LogType.USAGE_LOGS,
          destination: agentcore.LoggingDestination.cloudWatchLogs(foundation.runtimeLogGroup),
        },
      ],
      tags: {
        Application: 'ThreatForest',
        Environment: DEPLOYMENT.environment,
      },
    });
    const runtimeLog = encryptRuntimeLogGroup(
      this,
      this.runtime,
      foundation,
    );
    this.runtimeLogGroupName = runtimeLog.getAttString('LogGroupName');

    foundation.stateTable.grantReadWriteData(this.runtime);
    foundation.artifactsBucket.grantReadWrite(this.runtime);
    foundation.keys.actorHmac.grant(this.runtime, 'kms:GenerateMac');
    foundation.keys.state.grantDecrypt(this.runtime);
    foundation.keys.workflows.grantDecrypt(this.runtime);
    this.memory.grantRead(this.runtime);
    this.memory.grantWrite(this.runtime);
    this.runtime.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'UseAgentCoreMemoryEncryptionKey',
        actions: [
          'kms:CreateGrant',
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:GenerateDataKey',
          'kms:GenerateDataKeyWithoutPlaintext',
          'kms:ReEncrypt*',
        ],
        resources: [foundation.keys.memory.keyArn],
        conditions: {
          StringEquals: {
            'kms:ViaService':
              `bedrock-agentcore.${this.region}.${this.urlSuffix}`,
          },
        },
      }),
    );

    this.runtime.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'InvokeConfiguredModels',
        actions: [
          'bedrock:InvokeModel',
          'bedrock:InvokeModelWithResponseStream',
          'bedrock:GetInferenceProfile',
        ],
        resources: [
          Arn.format(
            {
              service: 'bedrock',
              region: '*',
              account: '',
              resource: 'foundation-model',
              resourceName: '*',
              arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
            },
            this,
          ),
          Arn.format(
            {
              service: 'bedrock',
              region: '*',
              account: this.account,
              resource: 'inference-profile',
              resourceName: '*',
              arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
            },
            this,
          ),
          Arn.format(
            {
              service: 'bedrock',
              region: '*',
              account: this.account,
              resource: 'application-inference-profile',
              resourceName: '*',
              arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
            },
            this,
          ),
        ],
      }),
    );
    this.runtime.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'DiscoverConfiguredModels',
        actions: ['bedrock:ListInferenceProfiles', 'bedrock:ListFoundationModels'],
        resources: ['*'],
      }),
    );
    this.runtime.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'ReadPerUserModelCredentials',
        actions: ['secretsmanager:GetSecretValue'],
        resources: [
          Arn.format(
            {
              service: 'secretsmanager',
              resource: 'secret',
              resourceName: `threatforest/${DEPLOYMENT.environment}/users/*`,
              arnFormat: ArnFormat.COLON_RESOURCE_NAME,
            },
            this,
          ),
        ],
      }),
    );

    const memoryResourcePolicy = new agentcore.CfnResourcePolicy(
      this,
      'MemoryResourcePolicy',
      {
        resourceArn: this.memory.memoryArn,
        policy: this.toJsonString({
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'RuntimeApplicationScopedMemory',
              Effect: 'Allow',
              Principal: { AWS: this.runtime.role.roleArn },
              Action: [
                'bedrock-agentcore:CreateEvent',
                'bedrock-agentcore:GetEvent',
                'bedrock-agentcore:ListEvents',
                'bedrock-agentcore:GetMemoryRecord',
                'bedrock-agentcore:RetrieveMemoryRecords',
                'bedrock-agentcore:ListMemoryRecords',
                'bedrock-agentcore:ListActors',
                'bedrock-agentcore:ListSessions',
              ],
              Resource: this.memory.memoryArn,
              Condition: {
                StringEquals: { 'aws:PrincipalAccount': this.account },
              },
            },
          ],
        }),
      },
    );
    memoryResourcePolicy.node.addDependency(this.memory);
    memoryResourcePolicy.node.addDependency(this.runtime);
    addVendedLogDelivery(
      this,
      'Memory',
      this.memory.memoryArn,
      foundation.memoryLogGroup,
    );

    const mmdsV2 = enforceMmdsV2(this, this.runtime, foundation);

    this.policyEngine = new agentcore.CfnPolicyEngine(
      this,
      'GatewayPolicyEngine',
      {
        name: 'ThreatForestPolicyEngine',
        description:
          'Fine-grained tenant authorization for ThreatForest MCP tools',
        encryptionKeyArn: foundation.keys.gateway.keyArn,
        tags: [
          { key: 'Application', value: 'ThreatForest' },
          { key: 'Environment', value: DEPLOYMENT.environment },
        ],
      },
    );
    this.policyEngine.applyRemovalPolicy(
      RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    );
    foundation.keys.gateway.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowAgentCorePolicyEncryption',
        effect: iam.Effect.ALLOW,
        principals: [
          new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
        ],
        actions: [
          'kms:Decrypt',
          'kms:DescribeKey',
          'kms:Encrypt',
          'kms:GenerateDataKey*',
          'kms:ReEncrypt*',
        ],
        resources: ['*'],
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': this.formatArn({
              service: 'bedrock-agentcore',
              resource: 'policy-engine',
              resourceName: '*',
            }),
          },
        },
      }),
    );

    const gatewayName = `${DEPLOYMENT.namePrefix}-gateway`;
    const gatewayRole = new iam.Role(this, 'GatewayRole', {
      assumedBy: new iam.ServicePrincipal(
        'bedrock-agentcore.amazonaws.com',
        {
          conditions: {
            StringEquals: { 'aws:SourceAccount': this.account },
            ArnLike: {
              'aws:SourceArn': this.formatArn({
                service: 'bedrock-agentcore',
                resource: 'gateway',
                resourceName: `${gatewayName}*`,
              }),
            },
          },
        },
      ),
      description: `Service role for Bedrock AgentCore Gateway ${gatewayName}`,
      inlinePolicies: {
        ThreatForestGatewayAccess: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              sid: 'EncryptGatewayData',
              actions: [
                'kms:CreateGrant',
                'kms:Decrypt',
                'kms:DescribeKey',
                'kms:Encrypt',
                'kms:GenerateDataKey*',
                'kms:GenerateDataKeyPair*',
                'kms:ReEncrypt*',
              ],
              resources: [foundation.keys.gateway.keyArn],
            }),
            new iam.PolicyStatement({
              sid: 'ReadThreatForestPolicyEngine',
              actions: ['bedrock-agentcore:GetPolicyEngine'],
              resources: [this.policyEngine.attrPolicyEngineArn],
            }),
            new iam.PolicyStatement({
              sid: 'EvaluateThreatForestPolicies',
              actions: [
                'bedrock-agentcore:AuthorizeAction',
                'bedrock-agentcore:PartiallyAuthorizeActions',
              ],
              resources: [
                this.policyEngine.attrPolicyEngineArn,
                this.formatArn({
                  service: 'bedrock-agentcore',
                  resource: 'gateway',
                  resourceName: `${gatewayName}-*`,
                }),
              ],
            }),
          ],
        }),
      },
    });

    this.gateway = new agentcore.Gateway(this, 'Gateway', {
      gatewayName,
      description: 'Authenticated MCP facade over ThreatForest application services',
      protocolConfiguration: new agentcore.McpProtocolConfiguration({
        instructions:
          'Use ThreatForest tools only for applications owned by the authenticated principal.',
        searchType: agentcore.McpGatewaySearchType.SEMANTIC,
        supportedVersions: [
          agentcore.MCPProtocolVersion.MCP_2025_06_18,
          agentcore.MCPProtocolVersion.MCP_2025_03_26,
        ],
      }),
      authorizerConfiguration: agentcore.GatewayAuthorizer.usingCognito({
        userPool,
        allowedClients: [userPoolClient],
        allowedScopes: ['openid'],
      }),
      kmsKey: foundation.keys.gateway,
      role: gatewayRole,
      tags: {
        Application: 'ThreatForest',
        Environment: DEPLOYMENT.environment,
      },
    });
    const gatewayResource = this.gateway.node.findChild(
      'Resource',
    ) as agentcore.CfnGateway;
    gatewayResource.policyEngineConfiguration = {
      arn: this.policyEngine.attrPolicyEngineArn,
      mode: 'ENFORCE',
    };
    gatewayResource.node.addDependency(this.policyEngine);
    gatewayResource.node.addDependency(memoryResource);
    addVendedLogDelivery(
      this,
      'Gateway',
      this.gateway.gatewayArn,
      foundation.gatewayLogGroup,
    );

    const sharedSpansLog = ensureSharedTraceLogGroup(
      this,
      foundation,
      'SharedSpansLog',
      SHARED_SPANS_LOG_GROUP,
    );
    const applicationSignalsLog = ensureSharedTraceLogGroup(
      this,
      foundation,
      'ApplicationSignalsLog',
      APPLICATION_SIGNALS_LOG_GROUP,
    );
    ensureManagedLogGroup(
      this,
      foundation,
      'BatchEvaluationLog',
      BATCH_EVALUATION_LOG_GROUP,
    );
    const transactionSearchParameters = {
      Destination: 'CloudWatchLogs',
    };
    const transactionSearchLogPolicy = new logs.ResourcePolicy(
      this,
      'TransactionSearchLogPolicy',
    );
    const transactionSearchLogArns = [
      'aws/spans',
      '/aws/application-signals/data',
      '/aws/bedrock-agentcore/runtimes/*',
    ].map(
      (resourceName) =>
        `${this.formatArn({
          service: 'logs',
          resource: 'log-group',
          resourceName,
          arnFormat: ArnFormat.COLON_RESOURCE_NAME,
        })}:log-stream:*`,
    );
    transactionSearchLogPolicy.document.addStatements(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('xray.amazonaws.com')],
        actions: ['logs:PutLogEvents'],
        resources: transactionSearchLogArns,
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': this.formatArn({
              service: 'xray',
              resource: '*',
            }),
          },
        },
      }),
    );
    const transactionSearch = new customResources.AwsCustomResource(
      this,
      'TransactionSearch',
      {
        onCreate: {
          service: 'XRay',
          action: 'updateTraceSegmentDestination',
          parameters: transactionSearchParameters,
          ignoreErrorCodesMatching: 'InvalidRequestException',
          physicalResourceId:
            customResources.PhysicalResourceId.of(
              'threatforest-transaction-search',
            ),
        },
        onUpdate: {
          service: 'XRay',
          action: 'updateTraceSegmentDestination',
          parameters: transactionSearchParameters,
          ignoreErrorCodesMatching: 'InvalidRequestException',
          physicalResourceId:
            customResources.PhysicalResourceId.of(
              'threatforest-transaction-search',
            ),
        },
        policy: customResources.AwsCustomResourcePolicy.fromSdkCalls({
          resources: customResources.AwsCustomResourcePolicy.ANY_RESOURCE,
        }),
        installLatestAwsSdk: false,
      },
    );
    transactionSearch.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutRetentionPolicy'],
        resources: [SHARED_SPANS_LOG_GROUP, APPLICATION_SIGNALS_LOG_GROUP].map(
          (resourceName) => `${this.formatArn({
            service: 'logs',
            resource: 'log-group',
            resourceName,
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          })}:*`,
        ),
      }),
    );
    // The first activation of Transaction Search also initializes Application
    // Signals. These permissions are needed in an account without its service
    // linked role/channel, even though the entry API is an X-Ray operation.
    transactionSearch.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['application-signals:StartDiscovery'],
        resources: ['*'],
      }),
    );
    const applicationSignalsRoleArn = this.formatArn({
      service: 'iam',
      region: '',
      resource: 'role',
      resourceName:
        'aws-service-role/application-signals.cloudwatch.amazonaws.com/AWSServiceRoleForCloudWatchApplicationSignals',
      arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
    });
    transactionSearch.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['iam:GetRole'],
        resources: [applicationSignalsRoleArn],
      }),
    );
    transactionSearch.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['iam:CreateServiceLinkedRole'],
        resources: [applicationSignalsRoleArn],
        conditions: {
          StringEquals: {
            'iam:AWSServiceName': 'application-signals.cloudwatch.amazonaws.com',
          },
        },
      }),
    );
    transactionSearch.grantPrincipal.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ['cloudtrail:CreateServiceLinkedChannel'],
        resources: [this.formatArn({
          service: 'cloudtrail',
          resource: 'channel',
          resourceName: 'aws-service-channel/application-signals/*',
          arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
        })],
      }),
    );
    transactionSearch.node.addDependency(transactionSearchLogPolicy);
    // Enabling Transaction Search creates these AWS-managed groups in a new
    // account. Only then can the providers attach encryption and retention.
    sharedSpansLog.node.addDependency(transactionSearch);
    applicationSignalsLog.node.addDependency(transactionSearch);

    const domainQualityEvaluator = new agentcore.Evaluator(
      this,
      'DomainQualityEvaluator',
      {
        evaluatorName: 'ThreatForestDomainQuality',
        description:
          'Evaluates completed ThreatForest TTP and mitigation quality gates',
        level: agentcore.EvaluationLevel.SESSION,
        evaluatorConfig: agentcore.EvaluatorConfig.llmAsAJudge({
          modelId: 'global.anthropic.claude-sonnet-4-6',
          instructions: [
            'Evaluate the completed ThreatForest session using {context}.',
            'Find the threatforest.run.output_quality span and use its deterministic attributes.',
            'Pass only when threatforest.quality.gate_passed is true, TTP decision coverage is 1,',
            'mitigation coverage is 1, and mitigation evidence coverage is 1.',
            'Explicit TTP abstentions are acceptable and must not be treated as failures.',
            'Do not claim semantic TTP correctness without human-labeled reference data.',
          ].join(' '),
          ratingScale: agentcore.EvaluatorRatingScale.categorical([
            {
              label: 'Pass',
              definition:
                'All deterministic TTP decision, mitigation coverage, and evidence gates passed.',
            },
            {
              label: 'NeedsReview',
              definition:
                'A required quality metric is missing or one or more deterministic gates failed.',
            },
          ]),
          inferenceConfig: {
            maxTokens: 512,
            temperature: 0,
          },
        }),
        tags: {
          Application: 'ThreatForest',
          Environment: DEPLOYMENT.environment,
        },
      },
    );

    const runtimeTraceLogGroupName =
      `/aws/bedrock-agentcore/runtimes/${this.runtime.agentRuntimeId}-DEFAULT`;
    this.onlineEvaluation = new agentcore.OnlineEvaluationConfig(this, 'OnlineEvaluation', {
      onlineEvaluationConfigName: 'ThreatForestEvaluation',
      description: 'Continuous quality evaluation for completed ThreatForest runs',
      dataSource: agentcore.DataSourceConfig.fromCloudWatchLogs({
        logGroupNames: [
          SHARED_SPANS_LOG_GROUP,
          runtimeTraceLogGroupName,
        ],
        serviceNames: [`${RUNTIME_NAME}.DEFAULT`],
      }),
      evaluators: [
        agentcore.EvaluatorSelector.builtin(agentcore.BuiltinEvaluator.RESPONSE_RELEVANCE),
        agentcore.EvaluatorSelector.custom(domainQualityEvaluator),
      ],
      samplingPercentage: 100,
      sessionTimeout: Duration.minutes(5),
      filters: [
        {
          key: 'name',
          operator: agentcore.FilterOperator.EQUAL,
          value: agentcore.FilterValue.string(
            'threatforest.run.output_quality',
          ),
        },
      ],
      executionStatus: agentcore.ExecutionStatus.ENABLED,
      tags: {
        Application: 'ThreatForest',
        Environment: DEPLOYMENT.environment,
      },
    });
    foundation.keys.telemetry.grantDecrypt(this.onlineEvaluation);
    this.onlineEvaluation.node.addDependency(transactionSearch);
    this.onlineEvaluation.node.addDependency(sharedSpansLog);
    this.onlineEvaluation.node.addDependency(applicationSignalsLog);
    this.onlineEvaluation.node.addDependency(mmdsV2);
    this.onlineEvaluation.node.addDependency(runtimeLog);
    const evaluationLog = encryptEvaluationLogGroup(
      this,
      this.onlineEvaluation,
      foundation,
    );
    this.evaluationLogGroupName =
      evaluationLog.getAttString('LogGroupName');

    new CfnOutput(this, 'RuntimeArn', { value: this.runtime.agentRuntimeArn });
    new CfnOutput(this, 'RuntimeLogGroupName', {
      value: this.runtimeLogGroupName,
    });
    new CfnOutput(this, 'MemoryId', { value: this.memory.memoryId });
    new CfnOutput(this, 'GatewayUrl', { value: this.gateway.gatewayUrl ?? this.gateway.gatewayArn });
    new CfnOutput(this, 'PolicyEngineArn', {
      value: this.policyEngine.attrPolicyEngineArn,
    });
    new CfnOutput(this, 'OnlineEvaluationArn', {
      value: this.onlineEvaluation.onlineEvaluationConfigArn,
    });
    new CfnOutput(this, 'EvaluationLogGroupName', {
      value: this.evaluationLogGroupName,
    });
  }
}
