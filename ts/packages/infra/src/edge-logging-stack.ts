import {
  ArnFormat,
  Duration,
  RemovalPolicy,
  Stack,
  Token,
  type StackProps,
  aws_iam as iam,
  aws_kms as kms,
  aws_logs as logs,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';

export interface EdgeLoggingStackProps extends StackProps {
  readonly distributionArn: string;
}

export class EdgeLoggingStack extends Stack {
  readonly accessLogEncryptionKey: kms.IKey;
  readonly accessLogGroup: logs.ILogGroup;

  constructor(scope: Construct, id: string, props: EdgeLoggingStackProps) {
    super(scope, id, props);

    if (!Token.isUnresolved(this.region) && this.region !== DEPLOYMENT.edgeRegion) {
      throw new Error(
        `CloudFront standard logging must be configured in ${DEPLOYMENT.edgeRegion}`,
      );
    }

    const accessLogGroupName =
      `/threatforest/${DEPLOYMENT.environment}/cloudfront-access`;
    this.accessLogEncryptionKey = new kms.Key(this, 'CloudFrontAccessLogKey', {
      alias: `alias/${DEPLOYMENT.namePrefix}/cloudfront-access-logs`,
      description: 'Encryption key for ThreatForest CloudFront access logs',
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    this.accessLogEncryptionKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudWatchLogsEncryption',
        principals: [
          new iam.ServicePrincipal(
            `logs.${DEPLOYMENT.edgeRegion}.amazonaws.com`,
          ),
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
            'kms:EncryptionContext:aws:logs:arn':
              `arn:aws:logs:${DEPLOYMENT.edgeRegion}:${this.account}:` +
              `log-group:${accessLogGroupName}`,
          },
        },
      }),
    );
    this.accessLogGroup = new logs.LogGroup(this, 'CloudFrontAccessLogs', {
      logGroupName: accessLogGroupName,
      encryptionKey: this.accessLogEncryptionKey,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });

    const deliveryPolicy = new logs.ResourcePolicy(
      this,
      'AccessLogDeliveryPolicy',
    );
    deliveryPolicy.document.addStatements(
      new iam.PolicyStatement({
        principals: [
          new iam.ServicePrincipal('delivery.logs.amazonaws.com'),
        ],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          this.formatArn({
            service: 'logs',
            resource: 'log-group',
            resourceName: `${accessLogGroupName}:log-stream:*`,
            arnFormat: ArnFormat.COLON_RESOURCE_NAME,
          }),
        ],
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': this.formatArn({
              service: 'logs',
              resource: '*',
            }),
          },
        },
      }),
    );

    const destination = new logs.CfnDeliveryDestination(
      this,
      'AccessLogDestination',
      {
        name: `${DEPLOYMENT.namePrefix}-cloudfront`,
        destinationResourceArn: this.accessLogGroup.logGroupArn,
        outputFormat: 'json',
      },
    );
    destination.node.addDependency(deliveryPolicy);
    const source = new logs.CfnDeliverySource(this, 'AccessLogSource', {
      name: `${DEPLOYMENT.namePrefix}-cloudfront`,
      resourceArn: props.distributionArn,
      logType: 'ACCESS_LOGS',
    });
    const delivery = new logs.CfnDelivery(this, 'AccessLogDelivery', {
      deliveryDestinationArn: destination.attrArn,
      deliverySourceName: source.name,
      recordFields: [
        'date',
        'time',
        'x-edge-location',
        'sc-bytes',
        'c-ip',
        'cs-method',
        'cs(Host)',
        'cs-uri-stem',
        'cs(User-Agent)',
        'sc-status',
        'x-edge-result-type',
        'x-edge-request-id',
        'x-host-header',
        'cs-protocol',
        'cs-bytes',
        'time-taken',
        'ssl-protocol',
        'ssl-cipher',
        'x-edge-response-result-type',
        'cs-protocol-version',
        'time-to-first-byte',
        'x-edge-detailed-result-type',
        'sc-content-type',
        'sc-content-len',
        'c-country',
        'cache-behavior-path-pattern',
      ],
    });
    delivery.addResourceDependency(destination);
    delivery.addResourceDependency(source);
  }
}
