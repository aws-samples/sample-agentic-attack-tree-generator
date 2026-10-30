import {
  ArnFormat,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
  aws_apigateway as apigateway,
  aws_dynamodb as dynamodb,
  aws_ec2 as ec2,
  aws_ecr as ecr,
  aws_iam as iam,
  aws_kms as kms,
  aws_logs as logs,
  aws_s3 as s3,
  aws_secretsmanager as secretsmanager,
  aws_servicediscovery as servicediscovery,
  aws_sqs as sqs,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';

export interface ThreatForestKeys {
  artifacts: kms.Key;
  state: kms.Key;
  memory: kms.Key;
  gateway: kms.Key;
  workflows: kms.Key;
  telemetry: kms.Key;
  build: kms.Key;
  actorHmac: kms.Key;
}

function retainedKey(scope: Construct, id: string, alias: string): kms.Key {
  const key = new kms.Key(scope, id, {
    alias: `alias/${DEPLOYMENT.namePrefix}/${alias}`,
    description: `ThreatForest ${alias} encryption key`,
    enableKeyRotation: true,
    pendingWindow: Duration.days(30),
    removalPolicy: RemovalPolicy.RETAIN,
  });
  key.applyRemovalPolicy(RemovalPolicy.RETAIN);
  return key;
}

function grantCloudWatchLogsEncryption(
  key: kms.IKey,
  stack: Stack,
  logGroupNamePatterns: readonly string[],
): void {
  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogsEncryption',
      principals: [
        new iam.ServicePrincipal(`logs.${stack.region}.${stack.urlSuffix}`),
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
          'kms:EncryptionContext:aws:logs:arn': logGroupNamePatterns.map(
            (logGroupNamePattern) =>
              stack.formatArn({
                service: 'logs',
                resource: 'log-group',
                resourceName: logGroupNamePattern,
                arnFormat: ArnFormat.COLON_RESOURCE_NAME,
              }),
          ),
        },
      },
    }),
  );
}

export class FoundationStack extends Stack {
  readonly vpc: ec2.Vpc;
  readonly ttpMapperNamespace: servicediscovery.PrivateDnsNamespace;
  readonly keys: ThreatForestKeys;
  readonly artifactsBucket: s3.Bucket;
  readonly webBucket: s3.Bucket;
  readonly accessLogsBucket: s3.Bucket;
  readonly stateTable: dynamodb.Table;
  readonly ingestionQueue: sqs.Queue;
  readonly ingestionDeadLetterQueue: sqs.Queue;
  readonly reportImportQueue: sqs.Queue;
  readonly reportImportDeadLetterQueue: sqs.Queue;
  readonly runCommandQueue: sqs.Queue;
  readonly runCommandDeadLetterQueue: sqs.Queue;
  readonly webSocketFanoutFailureQueue: sqs.Queue;
  readonly dispatchRelayFailureQueue: sqs.Queue;
  readonly runtimeRepository: ecr.Repository;
  readonly mapperRepository: ecr.Repository;
  readonly originCredential: secretsmanager.Secret;
  readonly replayTicketSecret: secretsmanager.Secret;
  readonly runtimeLogGroup: logs.LogGroup;
  readonly apiLogGroup: logs.LogGroup;
  readonly mcpLogGroup: logs.LogGroup;
  readonly webSocketLogGroup: logs.LogGroup;
  readonly webSocketFanoutLogGroup: logs.LogGroup;
  readonly dispatchRelayLogGroup: logs.LogGroup;
  readonly ingestionLogGroup: logs.LogGroup;
  readonly reportImportLogGroup: logs.LogGroup;
  readonly memoryLogGroup: logs.LogGroup;
  readonly gatewayLogGroup: logs.LogGroup;
  readonly workflowLogGroup: logs.LogGroup;
  readonly evaluationLogGroup: logs.LogGroup;

  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    this.keys = {
      artifacts: retainedKey(this, 'ArtifactsKey', 'artifacts'),
      state: retainedKey(this, 'StateKey', 'state'),
      memory: retainedKey(this, 'MemoryKey', 'memory'),
      gateway: retainedKey(this, 'GatewayKey', 'gateway'),
      workflows: retainedKey(this, 'WorkflowsKey', 'workflows'),
      telemetry: retainedKey(this, 'TelemetryKey', 'telemetry'),
      build: retainedKey(this, 'BuildKey', 'build'),
      actorHmac: new kms.Key(this, 'ActorHmacKey', {
        alias: `alias/${DEPLOYMENT.namePrefix}/actor-hmac`,
        description: 'HMAC key for deriving non-reversible AgentCore actor identifiers',
        keySpec: kms.KeySpec.HMAC_256,
        keyUsage: kms.KeyUsage.GENERATE_VERIFY_MAC,
        pendingWindow: Duration.days(30),
        removalPolicy: RemovalPolicy.RETAIN,
      }),
    };
    this.keys.actorHmac.applyRemovalPolicy(RemovalPolicy.RETAIN);
    grantCloudWatchLogsEncryption(
      this.keys.telemetry,
      this,
      [
        `/threatforest/${DEPLOYMENT.environment}/*`,
        'aws/spans',
        '/aws/application-signals/data',
        '/aws/bedrock-agentcore/evaluations/results/*',
        '/aws/bedrock-agentcore/evaluations/batch-evaluations/results/*',
        '/aws/bedrock-agentcore/runtimes/*',
      ],
    );
    this.keys.telemetry.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowLambdaFilterCriteriaDecryption',
        principals: [
          new iam.ServicePrincipal(
            `lambda.${this.region}.${this.urlSuffix}`,
          ),
        ],
        actions: ['kms:Decrypt'],
        resources: ['*'],
      }),
    );
    this.keys.telemetry.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowAgentCoreBatchEvaluationEncryption',
        principals: [
          new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
        ],
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: ['*'],
        conditions: {
          StringEquals: {
            'aws:SourceAccount': this.account,
          },
          ArnLike: {
            'aws:SourceArn': this.formatArn({
              service: 'bedrock-agentcore',
              resource: 'batch-evaluate',
              resourceName: '*',
            }),
          },
        },
      }),
    );

    const flowLogs = new logs.LogGroup(this, 'VpcFlowLogs', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/vpc-flow`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.42.0.0/16'),
      maxAzs: 2,
      natGateways: 2,
      restrictDefaultSecurityGroup: true,
      subnetConfiguration: [
        {
          name: 'public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: 'application',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 22,
        },
        {
          name: 'isolated',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
      flowLogs: {
        cloudwatch: {
          destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogs),
          trafficType: ec2.FlowLogTrafficType.ALL,
        },
      },
    });
    this.ttpMapperNamespace = new servicediscovery.PrivateDnsNamespace(
      this,
      'TtpMapperNamespace',
      {
        name: `${DEPLOYMENT.namePrefix}.internal`,
        vpc: this.vpc,
        description: 'Private service discovery for ThreatForest runtime services',
      },
    );
    const apiGatewayLogsRole = new iam.Role(this, 'ApiGatewayLogsRole', {
      assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com'),
      description: 'Regional API Gateway delivery role for CloudWatch access logs',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AmazonAPIGatewayPushToCloudWatchLogs',
        ),
      ],
    });
    new apigateway.CfnAccount(this, 'ApiGatewayAccount', {
      cloudWatchRoleArn: apiGatewayLogsRole.roleArn,
    });

    this.vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });
    this.vpc.addGatewayEndpoint('DynamoDbEndpoint', {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
    });

    const endpointSecurityGroup = new ec2.SecurityGroup(this, 'EndpointSecurityGroup', {
      vpc: this.vpc,
      allowAllOutbound: false,
      description: 'HTTPS from ThreatForest private subnets to AWS service endpoints',
    });
    endpointSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      'Private subnet HTTPS',
    );

    const interfaceEndpoints: Array<[string, ec2.InterfaceVpcEndpointService]> = [
      ['EcrApiEndpoint', ec2.InterfaceVpcEndpointAwsService.ECR],
      ['EcrDockerEndpoint', ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER],
      ['LogsEndpoint', ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
      ['KmsEndpoint', ec2.InterfaceVpcEndpointAwsService.KMS],
      ['SecretsEndpoint', ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ['SqsEndpoint', ec2.InterfaceVpcEndpointAwsService.SQS],
      ['StepFunctionsEndpoint', ec2.InterfaceVpcEndpointAwsService.STEP_FUNCTIONS],
      ['StsEndpoint', ec2.InterfaceVpcEndpointAwsService.STS],
      ['BedrockRuntimeEndpoint', ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME],
      ['BedrockAgentCoreEndpoint', ec2.InterfaceVpcEndpointAwsService.BEDROCK_AGENTCORE],
      [
        'BedrockAgentCoreControlEndpoint',
        new ec2.InterfaceVpcEndpointService(
          `com.amazonaws.${this.region}.bedrock-agentcore-control`,
        ),
      ],
      [
        'BedrockAgentCoreGatewayEndpoint',
        ec2.InterfaceVpcEndpointAwsService.BEDROCK_AGENTCORE_GATEWAY,
      ],
      ['TextractEndpoint', ec2.InterfaceVpcEndpointAwsService.TEXTRACT],
    ];
    for (const [endpointId, service] of interfaceEndpoints) {
      this.vpc.addInterfaceEndpoint(endpointId, {
        service,
        privateDnsEnabled: true,
        securityGroups: [endpointSecurityGroup],
        subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      });
    }

    this.accessLogsBucket = new s3.Bucket(this, 'AccessLogsBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.keys.telemetry,
      accessControl: s3.BucketAccessControl.LOG_DELIVERY_WRITE,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.OBJECT_WRITER,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [{ expiration: Duration.days(365) }],
    });

    this.artifactsBucket = new s3.Bucket(this, 'ArtifactsBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.keys.artifacts,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      serverAccessLogsBucket: this.accessLogsBucket,
      serverAccessLogsPrefix: 'artifacts/',
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          abortIncompleteMultipartUploadAfter: Duration.days(1),
          noncurrentVersionExpiration: Duration.days(365),
        },
      ],
      cors: [
        {
          allowedMethods: [
            s3.HttpMethods.GET,
            s3.HttpMethods.HEAD,
            s3.HttpMethods.PUT,
          ],
          allowedOrigins: ['*'],
          allowedHeaders: ['*'],
          exposedHeaders: [
            'Content-Disposition',
            'Content-Length',
            'Content-Type',
            'ETag',
            'x-amz-checksum-sha256',
          ],
          maxAge: 900,
        },
      ],
    });
    this.artifactsBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'DenyUnencryptedArtifactWrites',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:PutObject'],
        resources: [this.artifactsBucket.arnForObjects('*')],
        conditions: {
          StringNotEquals: {
            's3:x-amz-server-side-encryption': 'aws:kms',
          },
        },
      }),
    );
    this.artifactsBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'DenyWrongArtifactKey',
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:PutObject'],
        resources: [this.artifactsBucket.arnForObjects('*')],
        conditions: {
          StringNotEquals: {
            's3:x-amz-server-side-encryption-aws-kms-key-id': this.keys.artifacts.keyArn,
          },
        },
      }),
    );

    this.webBucket = new s3.Bucket(this, 'WebBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.keys.build,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      serverAccessLogsBucket: this.accessLogsBucket,
      serverAccessLogsPrefix: 'web/',
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.stateTable = new dynamodb.Table(this, 'StateTable', {
      partitionKey: { name: 'PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'SK', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.keys.state,
      deletionProtection: true,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      timeToLiveAttribute: 'ttl',
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.stateTable.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'GSI1PK', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'GSI1SK', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    this.ingestionDeadLetterQueue = new sqs.Queue(this, 'IngestionDeadLetterQueue', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.keys.workflows,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.ingestionQueue = new sqs.Queue(this, 'IngestionQueue', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.keys.workflows,
      enforceSSL: true,
      visibilityTimeout: Duration.minutes(15),
      retentionPeriod: Duration.days(14),
      deadLetterQueue: {
        queue: this.ingestionDeadLetterQueue,
        maxReceiveCount: 3,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.reportImportDeadLetterQueue = new sqs.Queue(
      this,
      'ReportImportDeadLetterQueue',
      {
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: this.keys.workflows,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.reportImportQueue = new sqs.Queue(this, 'ReportImportQueue', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.keys.workflows,
      enforceSSL: true,
      visibilityTimeout: Duration.minutes(20),
      retentionPeriod: Duration.days(14),
      deadLetterQueue: {
        queue: this.reportImportDeadLetterQueue,
        maxReceiveCount: 3,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.runCommandDeadLetterQueue = new sqs.Queue(
      this,
      'RunCommandDeadLetterQueue',
      {
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: this.keys.workflows,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.runCommandQueue = new sqs.Queue(this, 'RunCommandQueue', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.keys.workflows,
      enforceSSL: true,
      visibilityTimeout: Duration.minutes(20),
      retentionPeriod: Duration.days(14),
      deadLetterQueue: {
        queue: this.runCommandDeadLetterQueue,
        maxReceiveCount: 5,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.webSocketFanoutFailureQueue = new sqs.Queue(
      this,
      'WebSocketFanoutFailureQueue',
      {
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: this.keys.workflows,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.dispatchRelayFailureQueue = new sqs.Queue(
      this,
      'DispatchRelayFailureQueue',
      {
        encryption: sqs.QueueEncryption.KMS,
        encryptionMasterKey: this.keys.workflows,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );

    this.runtimeRepository = new ecr.Repository(this, 'RuntimeRepository', {
      repositoryName: `${DEPLOYMENT.namePrefix}-runtime`,
      encryption: ecr.RepositoryEncryption.KMS,
      encryptionKey: this.keys.build,
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.IMMUTABLE,
      removalPolicy: RemovalPolicy.RETAIN,
      emptyOnDelete: false,
      lifecycleRules: [{ maxImageCount: 50, tagStatus: ecr.TagStatus.ANY }],
    });
    this.mapperRepository = new ecr.Repository(this, 'MapperRepository', {
      repositoryName: `${DEPLOYMENT.namePrefix}-mapper`,
      encryption: ecr.RepositoryEncryption.KMS,
      encryptionKey: this.keys.build,
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.IMMUTABLE,
      removalPolicy: RemovalPolicy.RETAIN,
      emptyOnDelete: false,
      lifecycleRules: [{ maxImageCount: 25, tagStatus: ecr.TagStatus.ANY }],
    });

    this.originCredential = new secretsmanager.Secret(this, 'OriginCredential', {
      description: 'CloudFront origin verification credential',
      encryptionKey: this.keys.state,
      generateSecretString: { passwordLength: 64, excludePunctuation: true },
    });
    this.originCredential.applyRemovalPolicy(RemovalPolicy.RETAIN);
    this.replayTicketSecret = new secretsmanager.Secret(this, 'ReplayTicketSecret', {
      description: 'WebSocket replay ticket signing secret',
      encryptionKey: this.keys.state,
      generateSecretString: { passwordLength: 64, excludePunctuation: true },
    });
    this.replayTicketSecret.applyRemovalPolicy(RemovalPolicy.RETAIN);

    this.runtimeLogGroup = new logs.LogGroup(this, 'RuntimeLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/runtime`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.apiLogGroup = new logs.LogGroup(this, 'ApiLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/api`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.mcpLogGroup = new logs.LogGroup(this, 'McpLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/mcp`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.webSocketLogGroup = new logs.LogGroup(this, 'WebSocketLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/websocket`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.webSocketFanoutLogGroup = new logs.LogGroup(
      this,
      'WebSocketFanoutLogGroup',
      {
        logGroupName: `/threatforest/${DEPLOYMENT.environment}/websocket-fanout`,
        encryptionKey: this.keys.telemetry,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.dispatchRelayLogGroup = new logs.LogGroup(
      this,
      'DispatchRelayLogGroup',
      {
        logGroupName: `/threatforest/${DEPLOYMENT.environment}/dispatch-relay`,
        encryptionKey: this.keys.telemetry,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.ingestionLogGroup = new logs.LogGroup(this, 'IngestionLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/ingestion`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.reportImportLogGroup = new logs.LogGroup(
      this,
      'ReportImportLogGroup',
      {
        logGroupName: `/threatforest/${DEPLOYMENT.environment}/report-import`,
        encryptionKey: this.keys.telemetry,
        retention: logs.RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    this.memoryLogGroup = new logs.LogGroup(this, 'MemoryLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/memory`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.gatewayLogGroup = new logs.LogGroup(this, 'GatewayLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/gateway`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.workflowLogGroup = new logs.LogGroup(this, 'WorkflowLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/workflow`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.evaluationLogGroup = new logs.LogGroup(this, 'EvaluationLogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/evaluations`,
      encryptionKey: this.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });
  }
}
