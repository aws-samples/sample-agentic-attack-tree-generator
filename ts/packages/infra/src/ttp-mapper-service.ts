import { fileURLToPath } from 'node:url';
import {
  CfnOutput,
  Duration,
  IgnoreMode,
  RemovalPolicy,
  aws_ec2 as ec2,
  aws_ecr_assets as ecrAssets,
  aws_ecs as ecs,
  aws_logs as logs,
  aws_servicediscovery as servicediscovery,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';
import type { FoundationStack } from './foundation-stack.js';

export const TTP_MAPPER_PORT = 8770;
export const TTP_MAPPER_HEALTH_PATH = '/health';
export const TTP_MAPPER_SERVICE_NAME = 'ttp-mapper';
export const TTP_MAPPER_DOCKER_CONTEXT = fileURLToPath(
  new URL('../../../../', import.meta.url),
);
export const TTP_MAPPER_DOCKERFILE = 'src/ml_service/Dockerfile';

export interface TtpMapperServiceProps {
  readonly foundation: FoundationStack;
  readonly namespace: servicediscovery.IPrivateDnsNamespace;
  readonly runtimeSecurityGroup: ec2.ISecurityGroup;
  readonly imageTag?: string;
}

export class TtpMapperService extends Construct {
  readonly cluster: ecs.Cluster;
  readonly service: ecs.FargateService;
  readonly securityGroup: ec2.SecurityGroup;
  readonly url: string;

  constructor(scope: Construct, id: string, props: TtpMapperServiceProps) {
    super(scope, id);

    const { foundation, namespace, runtimeSecurityGroup } = props;
    const imageAsset =
      props.imageTag === undefined
        ? new ecrAssets.DockerImageAsset(this, 'Image', {
            directory: TTP_MAPPER_DOCKER_CONTEXT,
            file: TTP_MAPPER_DOCKERFILE,
            platform: ecrAssets.Platform.LINUX_AMD64,
            ignoreMode: IgnoreMode.GLOB,
            exclude: [
              '.git',
              '.github',
              '.venv',
              'Config',
              'archive_docs',
              'console-ui',
              'docs',
              'output',
              'paper',
              'sample-applications',
              'site',
              'threatforest-env',
              'ts',
              'venv',
            ],
          })
        : undefined;
    const image =
      imageAsset === undefined
        ? ecs.ContainerImage.fromEcrRepository(
            foundation.mapperRepository,
            props.imageTag,
          )
        : ecs.ContainerImage.fromDockerImageAsset(imageAsset);

    this.cluster = new ecs.Cluster(this, 'Cluster', {
      clusterName: `${DEPLOYMENT.namePrefix}-ml`,
      vpc: foundation.vpc,
      containerInsightsV2: ecs.ContainerInsights.ENHANCED,
      enableFargateCapacityProviders: true,
    });

    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `/threatforest/${DEPLOYMENT.environment}/ttp-mapper`,
      encryptionKey: foundation.keys.telemetry,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    const taskDefinition = new ecs.FargateTaskDefinition(
      this,
      'TaskDefinition',
      {
        cpu: 4096,
        memoryLimitMiB: 16384,
        ephemeralStorageGiB: 50,
        runtimePlatform: {
          cpuArchitecture: ecs.CpuArchitecture.X86_64,
          operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
        },
      },
    );
    const healthUrl = `http://127.0.0.1:${TTP_MAPPER_PORT}${TTP_MAPPER_HEALTH_PATH}`;
    const container = taskDefinition.addContainer('Container', {
      image,
      containerName: TTP_MAPPER_SERVICE_NAME,
      essential: true,
      environment: {
        TF_ML_HOST: '0.0.0.0',
        TF_ML_PORT: String(TTP_MAPPER_PORT),
        TF_ML_WARM: '1',
      },
      healthCheck: {
        command: [
          'CMD-SHELL',
          `python -c "import urllib.request; urllib.request.urlopen('${healthUrl}', timeout=5).read()"`,
        ],
        interval: Duration.seconds(30),
        retries: 5,
        startPeriod: Duration.minutes(5),
        timeout: Duration.seconds(10),
      },
      logging: ecs.LogDrivers.awsLogs({
        logGroup,
        streamPrefix: TTP_MAPPER_SERVICE_NAME,
        mode: ecs.AwsLogDriverMode.NON_BLOCKING,
      }),
      readonlyRootFilesystem: false,
      user: '10001:10001',
    });
    container.addPortMappings({
      name: 'http',
      containerPort: TTP_MAPPER_PORT,
      protocol: ecs.Protocol.TCP,
      appProtocol: ecs.AppProtocol.http,
    });

    this.securityGroup = new ec2.SecurityGroup(this, 'SecurityGroup', {
      vpc: foundation.vpc,
      allowAllOutbound: true,
      description: 'Only AgentCore Runtime may call the private TTP mapper',
    });
    this.securityGroup.addIngressRule(
      runtimeSecurityGroup,
      ec2.Port.tcp(TTP_MAPPER_PORT),
      'AgentCore Runtime to TTP mapper',
    );

    this.service = new ecs.FargateService(this, 'Service', {
      cluster: this.cluster,
      taskDefinition,
      serviceName: `${DEPLOYMENT.namePrefix}-${TTP_MAPPER_SERVICE_NAME}`,
      desiredCount: 2,
      assignPublicIp: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [this.securityGroup],
      platformVersion: ecs.FargatePlatformVersion.VERSION1_4,
      circuitBreaker: { enable: true, rollback: true },
      enableECSManagedTags: true,
      propagateTags: ecs.PropagatedTagSource.SERVICE,
      cloudMapOptions: {
        cloudMapNamespace: namespace,
        name: TTP_MAPPER_SERVICE_NAME,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: Duration.seconds(10),
        failureThreshold: 1,
      },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
    });
    this.service
      .autoScaleTaskCount({ minCapacity: 2, maxCapacity: 8 })
      .scaleOnCpuUtilization('CpuScaling', {
        targetUtilizationPercent: 60,
        scaleInCooldown: Duration.minutes(5),
        scaleOutCooldown: Duration.minutes(1),
      });

    this.url = `http://${TTP_MAPPER_SERVICE_NAME}.${namespace.namespaceName}:${TTP_MAPPER_PORT}`;
    new CfnOutput(this, 'Url', {
      value: this.url,
      description: 'Private AgentCore-only TTP mapper endpoint',
    });
  }
}
