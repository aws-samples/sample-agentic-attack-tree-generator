import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { App, Stack, aws_cognito as cognito } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AgentCoreStack } from '../src/agentcore-stack.js';
import { FoundationStack } from '../src/foundation-stack.js';
import {
  TTP_MAPPER_DOCKER_CONTEXT,
  TTP_MAPPER_DOCKERFILE,
} from '../src/ttp-mapper-service.js';

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
    runtimeImageTag: 'runtime-test',
    mapperImageTag: 'mapper-test',
  });
  return Template.fromStack(stack);
}

test('mapper source and Docker context preserve the Python service contract', () => {
  const dockerfilePath = join(
    TTP_MAPPER_DOCKER_CONTEXT,
    TTP_MAPPER_DOCKERFILE,
  );
  const appPath = join(TTP_MAPPER_DOCKER_CONTEXT, 'src/ml_service/app.py');
  const mainPath = join(TTP_MAPPER_DOCKER_CONTEXT, 'src/ml_service/__main__.py');
  const configPath = join(
    TTP_MAPPER_DOCKER_CONTEXT,
    'src/ml_service/container-config.yaml',
  );
  assert.ok(existsSync(join(TTP_MAPPER_DOCKER_CONTEXT, 'pyproject.toml')));
  assert.ok(existsSync(dockerfilePath));
  assert.ok(existsSync(configPath));

  const dockerfile = readFileSync(dockerfilePath, 'utf8');
  assert.match(dockerfile, /COPY --chown=10001:10001 src\/ml_service \.\/src\/ml_service/);
  assert.match(dockerfile, /COPY --chown=10001:10001 src\/threatforest \.\/src\/threatforest/);
  assert.match(dockerfile, /TF_ML_HOST=0\.0\.0\.0/);
  assert.match(dockerfile, /EXPOSE 8770/);
  assert.match(dockerfile, /127\.0\.0\.1:8770\/health/);

  assert.match(readFileSync(appPath, 'utf8'), /@app\.get\("\/health"\)/);
  assert.match(
    readFileSync(mainPath, 'utf8'),
    /os\.environ\.get\("TF_ML_PORT", "8770"\)/,
  );
});

test('mapper runs privately on Fargate with health checks and service discovery', () => {
  const value = template();
  value.resourceCountIs('AWS::ECS::Cluster', 1);
  value.resourceCountIs('AWS::ECS::Service', 1);
  value.resourceCountIs('AWS::ECS::TaskDefinition', 1);
  value.resourceCountIs('AWS::ServiceDiscovery::PrivateDnsNamespace', 0);
  const logGroup = Object.values(
    value.findResources('AWS::Logs::LogGroup'),
  ).find(
    (resource) =>
      (resource as { Properties?: { LogGroupName?: string } }).Properties
        ?.LogGroupName === '/threatforest/test/ttp-mapper',
  ) as {
    DeletionPolicy: string;
    UpdateReplacePolicy: string;
  };
  assert.equal(logGroup.DeletionPolicy, 'RetainExceptOnCreate');
  assert.equal(logGroup.UpdateReplacePolicy, 'Retain');
  value.hasResourceProperties('AWS::ECS::Service', {
    ServiceRegistries: Match.arrayWith([
      Match.objectLike({
        RegistryArn: Match.anyValue(),
      }),
    ]),
  });
  value.hasResourceProperties('AWS::ECS::TaskDefinition', {
    Cpu: '4096',
    EphemeralStorage: { SizeInGiB: 50 },
    Memory: '16384',
    NetworkMode: 'awsvpc',
    RequiresCompatibilities: ['FARGATE'],
    RuntimePlatform: {
      CpuArchitecture: 'X86_64',
      OperatingSystemFamily: 'LINUX',
    },
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({
        Environment: Match.arrayWith([
          { Name: 'TF_ML_HOST', Value: '0.0.0.0' },
          { Name: 'TF_ML_PORT', Value: '8770' },
          { Name: 'TF_ML_WARM', Value: '1' },
        ]),
        HealthCheck: Match.objectLike({
          Command: Match.arrayWith([
            'CMD-SHELL',
            Match.stringLikeRegexp('127.0.0.1:8770/health'),
          ]),
          StartPeriod: 300,
        }),
        LogConfiguration: Match.objectLike({
          LogDriver: 'awslogs',
        }),
        PortMappings: [
          {
            AppProtocol: 'http',
            ContainerPort: 8770,
            Name: 'http',
            Protocol: 'tcp',
          },
        ],
        User: '10001:10001',
      }),
    ]),
  });
  const taskDefinition = Object.values(
    value.findResources('AWS::ECS::TaskDefinition'),
  )[0] as { Properties: { ContainerDefinitions: Array<{ Image: unknown }> } };
  assert.match(
    JSON.stringify(taskDefinition.Properties.ContainerDefinitions[0]?.Image),
    /mapper-test/,
  );
  value.hasResourceProperties('AWS::ECS::Service', {
    DesiredCount: 2,
    EnableECSManagedTags: true,
    LaunchType: 'FARGATE',
    NetworkConfiguration: {
      AwsvpcConfiguration: Match.objectLike({
        AssignPublicIp: 'DISABLED',
        SecurityGroups: Match.anyValue(),
        Subnets: Match.anyValue(),
      }),
    },
    ServiceRegistries: Match.anyValue(),
  });
  value.hasResourceProperties('AWS::EC2::SecurityGroupIngress', {
    Description: 'AgentCore Runtime to TTP mapper',
    FromPort: 8770,
    IpProtocol: 'tcp',
    SourceSecurityGroupId: Match.anyValue(),
    ToPort: 8770,
  });
});

test('AgentCore receives only the private mapper URL', () => {
  const value = template();
  value.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
    EnvironmentVariables: Match.objectLike({
      TF_ML_URL: 'http://ttp-mapper.threatforest-test.internal:8770',
    }),
  });
  assert.equal(
    Object.keys(value.findResources('AWS::ElasticLoadBalancingV2::LoadBalancer'))
      .length,
    0,
  );
});
