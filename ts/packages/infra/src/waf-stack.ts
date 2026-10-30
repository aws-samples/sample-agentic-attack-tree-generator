import {
  ArnFormat,
  Duration,
  RemovalPolicy,
  Stack,
  Token,
  type StackProps,
  aws_cloudwatch as cloudwatch,
  aws_iam as iam,
  aws_kms as kms,
  aws_logs as logs,
  aws_wafv2 as wafv2,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import { DEPLOYMENT } from './config.js';

export interface WafStackProps extends StackProps {
  readonly rateLimitPerFiveMinutes?: number;
  readonly blockedRequestAlarmThreshold?: number;
  readonly logEncryptionKey?: kms.IKey;
}

function visibilityConfig(metricName: string): wafv2.CfnWebACL.VisibilityConfigProperty {
  return {
    cloudWatchMetricsEnabled: true,
    metricName,
    sampledRequestsEnabled: false,
  };
}

function managedRule(
  name: string,
  managedRuleGroupName: string,
  priority: number,
): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: {
      managedRuleGroupStatement: {
        name: managedRuleGroupName,
        vendorName: 'AWS',
      },
    },
    visibilityConfig: visibilityConfig(`${DEPLOYMENT.namePrefix}-${name}`),
  };
}

export class WafStack extends Stack {
  readonly webAcl: wafv2.CfnWebACL;
  readonly webAclArn: string;
  readonly logEncryptionKey: kms.IKey;
  readonly logGroup: logs.LogGroup;
  readonly blockedRequestAlarm: cloudwatch.Alarm;

  constructor(scope: Construct, id: string, props: WafStackProps = {}) {
    super(scope, id, props);

    if (!Token.isUnresolved(this.region) && this.region !== DEPLOYMENT.edgeRegion) {
      throw new Error(`CloudFront WAF resources must deploy in ${DEPLOYMENT.edgeRegion}`);
    }

    const rateLimit = props.rateLimitPerFiveMinutes ?? 2_000;
    const alarmThreshold = props.blockedRequestAlarmThreshold ?? 100;
    if (rateLimit < 1 || alarmThreshold < 1) {
      throw new Error('WAF rate and alarm thresholds must be positive integers');
    }

    this.logEncryptionKey =
      props.logEncryptionKey ??
      new kms.Key(this, 'WafLogKey', {
        alias: `alias/${DEPLOYMENT.namePrefix}/waf-logs`,
        description: 'Encryption key for ThreatForest WAF logs',
        enableKeyRotation: true,
        pendingWindow: Duration.days(30),
        removalPolicy: RemovalPolicy.RETAIN,
      });
    if (!props.logEncryptionKey) {
      this.logEncryptionKey.applyRemovalPolicy(RemovalPolicy.RETAIN);
    }
    this.logEncryptionKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudWatchLogsEncryption',
        principals: [
          new iam.ServicePrincipal(`logs.${this.region}.${this.urlSuffix}`),
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
            'kms:EncryptionContext:aws:logs:arn': this.formatArn({
              service: 'logs',
              resource: 'log-group',
              resourceName: `aws-waf-logs-${DEPLOYMENT.namePrefix}-edge*`,
              arnFormat: ArnFormat.COLON_RESOURCE_NAME,
            }),
          },
        },
      }),
    );

    this.logGroup = new logs.LogGroup(this, 'WafLogGroup', {
      logGroupName: `aws-waf-logs-${DEPLOYMENT.namePrefix}-edge`,
      encryptionKey: this.logEncryptionKey,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const webAclName = `${DEPLOYMENT.namePrefix}-edge`;
    this.webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: webAclName,
      description: 'ThreatForest CloudFront web ACL',
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: visibilityConfig(`${DEPLOYMENT.namePrefix}-web-acl`),
      rules: [
        managedRule('IpReputation', 'AWSManagedRulesAmazonIpReputationList', 0),
        managedRule('KnownBadInputs', 'AWSManagedRulesKnownBadInputsRuleSet', 1),
        managedRule('Common', 'AWSManagedRulesCommonRuleSet', 2),
        {
          name: 'PerIpRateLimit',
          priority: 3,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              aggregateKeyType: 'IP',
              evaluationWindowSec: 300,
              limit: rateLimit,
            },
          },
          visibilityConfig: visibilityConfig(`${DEPLOYMENT.namePrefix}-rate-limit`),
        },
      ],
    });
    this.webAclArn = this.webAcl.attrArn;

    const logging = new wafv2.CfnLoggingConfiguration(this, 'WafLogging', {
      resourceArn: this.webAcl.attrArn,
      logDestinationConfigs: [this.logGroup.logGroupArn],
      redactedFields: [
        { singleHeader: { Name: 'authorization' } },
        { singleHeader: { Name: 'cookie' } },
        { queryString: {} },
      ],
      loggingFilter: {
        DefaultBehavior: 'DROP',
        Filters: [
          {
            Behavior: 'KEEP',
            Conditions: [{ ActionCondition: { Action: 'BLOCK' } }],
            Requirement: 'MEETS_ANY',
          },
        ],
      },
    });
    logging.addResourceDependency(this.logGroup.node.defaultChild as logs.CfnLogGroup);

    const blockedRequests = new cloudwatch.Metric({
      namespace: 'AWS/WAFV2',
      metricName: 'BlockedRequests',
      dimensionsMap: {
        WebACL: webAclName,
        Rule: 'ALL',
        Region: 'Global',
      },
      statistic: 'Sum',
      period: Duration.minutes(5),
    });

    this.blockedRequestAlarm = new cloudwatch.Alarm(this, 'BlockedRequestAlarm', {
      alarmName: `${DEPLOYMENT.namePrefix}-waf-blocked-requests`,
      alarmDescription: 'ThreatForest WAF blocked request volume exceeded its expected baseline',
      metric: blockedRequests,
      threshold: alarmThreshold,
      evaluationPeriods: 1,
      datapointsToAlarm: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
  }
}
