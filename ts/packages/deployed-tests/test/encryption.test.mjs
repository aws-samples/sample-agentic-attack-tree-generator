import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertDeploymentAccount,
  awsJson,
  requiredAwsEnvironment,
} from './support/aws-cli.mjs';
import { optional, skipUnless } from './support/env.mjs';

test(
  'artifact bucket and DynamoDB state use the expected customer KMS key',
  {
    skip: skipUnless(
      'TF_ARTIFACT_BUCKET',
      'TF_STATE_TABLE',
      'TF_ARTIFACT_KMS_KEY_ARN',
      'TF_STATE_KMS_KEY_ARN',
    ),
  },
  () => {
    assertDeploymentAccount();
    const { bucket, table, artifactKeyArn, stateKeyArn } =
      requiredAwsEnvironment();
    const bucketEncryption = awsJson(
      's3api',
      'get-bucket-encryption',
      '--bucket',
      bucket,
    );
    const rules =
      bucketEncryption.ServerSideEncryptionConfiguration?.Rules || [];
    assert.equal(
      rules.some(
        (rule) =>
          rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'aws:kms' &&
          rule.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID ===
            artifactKeyArn &&
          rule.BucketKeyEnabled === true,
      ),
      true,
    );

    const tableDescription = awsJson(
      'dynamodb',
      'describe-table',
      '--table-name',
      table,
    ).Table;
    assert.equal(tableDescription.SSEDescription?.Status, 'ENABLED');
    assert.equal(tableDescription.SSEDescription?.SSEType, 'KMS');
    assert.equal(
      tableDescription.SSEDescription?.KMSMasterKeyArn,
      stateKeyArn,
    );
    assert.equal(tableDescription.PointInTimeRecoveryDescription, undefined);
    const recovery = awsJson(
      'dynamodb',
      'describe-continuous-backups',
      '--table-name',
      table,
    );
    assert.equal(
      recovery.ContinuousBackupsDescription?.PointInTimeRecoveryDescription
        ?.PointInTimeRecoveryStatus,
      'ENABLED',
    );
  },
);

test(
  'a supplied uploaded artifact is encrypted with the artifact KMS key',
  {
    skip:
      skipUnless('TF_ARTIFACT_BUCKET', 'TF_ARTIFACT_KMS_KEY_ARN') ||
      (optional('TF_TEST_ARTIFACT_KEY') === null
        ? 'Set TF_TEST_ARTIFACT_KEY to inspect an uploaded object.'
        : false),
  },
  () => {
    const metadata = awsJson(
      's3api',
      'head-object',
      '--bucket',
      optional('TF_ARTIFACT_BUCKET'),
      '--key',
      optional('TF_TEST_ARTIFACT_KEY'),
    );
    assert.equal(metadata.ServerSideEncryption, 'aws:kms');
    assert.equal(metadata.SSEKMSKeyId, optional('TF_ARTIFACT_KMS_KEY_ARN'));
    assert.equal(metadata.BucketKeyEnabled, true);
  },
);
