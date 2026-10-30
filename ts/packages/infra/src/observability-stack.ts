import {
  CfnOutput,
  Duration,
  Stack,
  type StackProps,
  aws_cloudwatch as cloudwatch,
  aws_cloudwatch_actions as actions,
  aws_dynamodb as dynamodb,
  aws_logs as logs,
  aws_sns as sns,
  aws_stepfunctions as stepfunctions,
} from 'aws-cdk-lib';
import type { Construct } from 'constructs';
import type { AgentCoreStack } from './agentcore-stack.js';
import { DEPLOYMENT } from './config.js';
import type { FoundationStack } from './foundation-stack.js';

export interface ObservabilityStackProps extends StackProps {
  readonly foundation: FoundationStack;
  readonly agentCore: AgentCoreStack;
  readonly workflow?: stepfunctions.IStateMachine;
  readonly httpApiId?: string;
  readonly webSocketApiId?: string;
}

export class ObservabilityStack extends Stack {
  readonly dashboard: cloudwatch.Dashboard;
  readonly alarmTopic: sns.Topic;
  readonly serviceHealthAlarm: cloudwatch.CompositeAlarm;

  constructor(scope: Construct, id: string, props: ObservabilityStackProps) {
    super(scope, id, props);

    const { foundation, agentCore } = props;
    this.alarmTopic = new sns.Topic(this, 'AlarmTopic', {
      topicName: `${DEPLOYMENT.namePrefix}-alarms`,
      displayName: 'ThreatForest hosted alarms',
      masterKey: foundation.keys.workflows,
    });
    const alarmAction = new actions.SnsAction(this.alarmTopic);

    const runtimeErrors = new logs.MetricFilter(this, 'RuntimeErrorMetric', {
      logGroup: foundation.runtimeLogGroup,
      filterPattern: logs.FilterPattern.anyTerm('ERROR', 'Error', 'error'),
      metricNamespace: 'ThreatForest',
      metricName: 'RuntimeLogErrors',
      metricValue: '1',
      defaultValue: 0,
    }).metric({ statistic: 'Sum', period: Duration.minutes(5) });
    const apiErrors = new logs.MetricFilter(this, 'ApiErrorMetric', {
      logGroup: foundation.apiLogGroup,
      filterPattern: logs.FilterPattern.anyTerm('ERROR', 'Error', 'error'),
      metricNamespace: 'ThreatForest',
      metricName: 'ApiLogErrors',
      metricValue: '1',
      defaultValue: 0,
    }).metric({ statistic: 'Sum', period: Duration.minutes(5) });
    const dispatchRelayFailures = new logs.MetricFilter(
      this,
      'DispatchRelayFailureMetric',
      {
        logGroup: foundation.dispatchRelayLogGroup,
        filterPattern: logs.FilterPattern.anyTerm(
          'threatforest.dispatch_relay.failed',
        ),
        metricNamespace: 'ThreatForest',
        metricName: 'DispatchRelayFailures',
        metricValue: '1',
        defaultValue: 0,
      },
    ).metric({ statistic: 'Sum', period: Duration.minutes(5) });
    const webSocketFanoutFailures = new logs.MetricFilter(
      this,
      'WebSocketFanoutFailureMetric',
      {
        logGroup: foundation.webSocketFanoutLogGroup,
        filterPattern: logs.FilterPattern.anyTerm(
          'threatforest.websocket_fanout.failed',
        ),
        metricNamespace: 'ThreatForest',
        metricName: 'WebSocketFanoutFailures',
        metricValue: '1',
        defaultValue: 0,
      },
    ).metric({ statistic: 'Sum', period: Duration.minutes(5) });

    const runtimeAlarm = new cloudwatch.Alarm(this, 'RuntimeErrorAlarm', {
      alarmName: `${DEPLOYMENT.namePrefix}-runtime-errors`,
      metric: runtimeErrors,
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    const apiAlarm = new cloudwatch.Alarm(this, 'ApiErrorAlarm', {
      alarmName: `${DEPLOYMENT.namePrefix}-api-errors`,
      metric: apiErrors,
      threshold: 5,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    const deliveryFailureQueueMessages = new cloudwatch.MathExpression({
      expression:
        'ingestion + reportImport + runCommand + dispatchRelay + websocketFanout',
      usingMetrics: {
        ingestion:
          foundation.ingestionDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
            period: Duration.minutes(1),
            statistic: 'Maximum',
          }),
        reportImport:
          foundation.reportImportDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
            period: Duration.minutes(1),
            statistic: 'Maximum',
          }),
        runCommand:
          foundation.runCommandDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
            period: Duration.minutes(1),
            statistic: 'Maximum',
          }),
        dispatchRelay:
          foundation.dispatchRelayFailureQueue.metricApproximateNumberOfMessagesVisible({
            period: Duration.minutes(1),
            statistic: 'Maximum',
          }),
        websocketFanout:
          foundation.webSocketFanoutFailureQueue.metricApproximateNumberOfMessagesVisible({
            period: Duration.minutes(1),
            statistic: 'Maximum',
          }),
      },
      period: Duration.minutes(1),
      label: 'Delivery failure queue messages',
    });
    const deadLetterAlarm = new cloudwatch.Alarm(this, 'DeadLetterAlarm', {
      alarmName: `${DEPLOYMENT.namePrefix}-delivery-failure-queues`,
      metric: deliveryFailureQueueMessages,
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    const dispatchRelayAlarm = new cloudwatch.Alarm(
      this,
      'DispatchRelayFailureAlarm',
      {
        alarmName: `${DEPLOYMENT.namePrefix}-dispatch-relay-failures`,
        metric: dispatchRelayFailures,
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    const webSocketFanoutAlarm = new cloudwatch.Alarm(
      this,
      'WebSocketFanoutFailureAlarm',
      {
        alarmName: `${DEPLOYMENT.namePrefix}-websocket-fanout-failures`,
        metric: webSocketFanoutFailures,
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    const stateSystemErrors = new cloudwatch.MathExpression({
      expression: 'writeErrors + readErrors',
      usingMetrics: {
        writeErrors: foundation.stateTable.metricSystemErrorsForOperations({
          operations: [
            dynamodb.Operation.BATCH_WRITE_ITEM,
            dynamodb.Operation.DELETE_ITEM,
            dynamodb.Operation.PUT_ITEM,
            dynamodb.Operation.TRANSACT_WRITE_ITEMS,
            dynamodb.Operation.UPDATE_ITEM,
          ],
          period: Duration.minutes(5),
          statistic: 'Sum',
        }),
        readErrors: foundation.stateTable.metricSystemErrorsForOperations({
          operations: [
            dynamodb.Operation.BATCH_GET_ITEM,
            dynamodb.Operation.GET_ITEM,
            dynamodb.Operation.QUERY,
            dynamodb.Operation.SCAN,
            dynamodb.Operation.TRANSACT_GET_ITEMS,
          ],
          period: Duration.minutes(5),
          statistic: 'Sum',
        }),
      },
      period: Duration.minutes(5),
      label: 'DynamoDB system errors',
    });
    const stateErrors = new cloudwatch.Alarm(this, 'StateSystemErrorAlarm', {
      alarmName: `${DEPLOYMENT.namePrefix}-state-system-errors`,
      metric: stateSystemErrors,
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    for (const alarm of [
      runtimeAlarm,
      apiAlarm,
      deadLetterAlarm,
      dispatchRelayAlarm,
      webSocketFanoutAlarm,
      stateErrors,
    ]) {
      alarm.addAlarmAction(alarmAction);
      alarm.addOkAction(alarmAction);
    }

    const componentAlarms: cloudwatch.IAlarm[] = [
      runtimeAlarm,
      apiAlarm,
      deadLetterAlarm,
      dispatchRelayAlarm,
      webSocketFanoutAlarm,
      stateErrors,
    ];
    if (props.workflow) {
      const workflowFailures = new cloudwatch.Alarm(this, 'WorkflowFailureAlarm', {
        alarmName: `${DEPLOYMENT.namePrefix}-workflow-failures`,
        metric: props.workflow.metricFailed({
          period: Duration.minutes(5),
          statistic: 'Sum',
        }),
        threshold: 1,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      workflowFailures.addAlarmAction(alarmAction);
      workflowFailures.addOkAction(alarmAction);
      componentAlarms.push(workflowFailures);
    }
    this.serviceHealthAlarm = new cloudwatch.CompositeAlarm(this, 'ServiceHealthAlarm', {
      compositeAlarmName: `${DEPLOYMENT.namePrefix}-service-health`,
      alarmRule: cloudwatch.AlarmRule.anyOf(
        ...componentAlarms.map((alarm) =>
          cloudwatch.AlarmRule.fromAlarm(alarm, cloudwatch.AlarmState.ALARM),
        ),
      ),
    });
    this.serviceHealthAlarm.addAlarmAction(alarmAction);
    this.serviceHealthAlarm.addOkAction(alarmAction);

    const runtimeInvocations = new cloudwatch.Metric({
      namespace: 'AWS/Bedrock-AgentCore',
      metricName: 'Invocations',
      dimensionsMap: { Runtime: agentCore.runtime.agentRuntimeName },
      statistic: 'Sum',
      period: Duration.minutes(5),
    });
    const runtimeLatency = new cloudwatch.Metric({
      namespace: 'AWS/Bedrock-AgentCore',
      metricName: 'Latency',
      dimensionsMap: { Runtime: agentCore.runtime.agentRuntimeName },
      statistic: 'p95',
      period: Duration.minutes(5),
    });
    const apiMetrics: cloudwatch.IMetric[] = [];
    if (props.httpApiId) {
      apiMetrics.push(
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: '5xx',
          dimensionsMap: { ApiId: props.httpApiId },
          statistic: 'Sum',
          period: Duration.minutes(5),
        }),
      );
    }
    if (props.webSocketApiId) {
      apiMetrics.push(
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: 'IntegrationError',
          dimensionsMap: { ApiId: props.webSocketApiId },
          statistic: 'Sum',
          period: Duration.minutes(5),
        }),
      );
    }

    this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
      dashboardName: `${DEPLOYMENT.namePrefix}-operations`,
      periodOverride: cloudwatch.PeriodOverride.AUTO,
      start: '-PT6H',
    });
    this.dashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'Service health',
        metrics: [
          runtimeErrors,
          apiErrors,
          deliveryFailureQueueMessages,
          dispatchRelayFailures,
          webSocketFanoutFailures,
          stateSystemErrors,
        ],
        width: 24,
      }),
      new cloudwatch.GraphWidget({
        title: 'AgentCore Runtime',
        left: [runtimeInvocations],
        right: [runtimeLatency],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: 'API and workflow failures',
        left: apiMetrics,
        width: 12,
      }),
      new cloudwatch.LogQueryWidget({
        title: 'Recent application errors',
        logGroupNames: [
          foundation.apiLogGroup.logGroupName,
          foundation.mcpLogGroup.logGroupName,
          foundation.webSocketLogGroup.logGroupName,
          foundation.webSocketFanoutLogGroup.logGroupName,
          foundation.dispatchRelayLogGroup.logGroupName,
          foundation.runtimeLogGroup.logGroupName,
          foundation.ingestionLogGroup.logGroupName,
          foundation.workflowLogGroup.logGroupName,
          foundation.memoryLogGroup.logGroupName,
          foundation.gatewayLogGroup.logGroupName,
          agentCore.evaluationLogGroupName,
        ],
        queryString: [
          'fields @timestamp, @log, @message',
          'filter @message like /(?i)(error|failed|exception)/',
          'sort @timestamp desc',
          'limit 100',
        ].join('\n'),
        view: cloudwatch.LogQueryVisualizationType.TABLE,
        width: 24,
      }),
    );

    new CfnOutput(this, 'DashboardName', { value: this.dashboard.dashboardName });
    new CfnOutput(this, 'AlarmTopicArn', { value: this.alarmTopic.topicArn });
  }
}
