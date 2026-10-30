/**
 * Shared by the CDK app and the dependency-free deployment shell helpers.
 * Keep existing resource names stable when updating the original deployment.
 *
 * @param {Record<string, string | undefined>} environment
 * @param {boolean} requireAccount
 */
export function resolveDeployment(environment = process.env, requireAccount = false) {
  const account = environment.TF_ACCOUNT_ID || environment.CDK_DEFAULT_ACCOUNT || '';
  const region = environment.TF_REGION || 'eu-west-2';
  const stage = environment.TF_ENVIRONMENT || 'test';
  if ((requireAccount || account) && !/^\d{12}$/.test(account)) {
    throw new Error('Set TF_ACCOUNT_ID to a 12-digit AWS account ID, or use the deployment scripts to discover it from your AWS credentials.');
  }
  if (!/^(us|eu|ap|ca|sa|me|af|il|mx)-(?!gov-|iso)[a-z]+-\d+$/.test(region)) {
    throw new Error('TF_REGION must be a commercial AWS Region, for example eu-west-2. GovCloud and China partitions are not supported by this deployment.');
  }
  if (!/^[a-z][a-z0-9-]{0,15}$/.test(stage)) {
    throw new Error('TF_ENVIRONMENT must be 1–16 lowercase letters, digits, or hyphens, starting with a letter.');
  }
  return Object.freeze({
    account,
    region,
    edgeRegion: 'us-east-1',
    environment: stage,
    namePrefix: `threatforest-${stage}`,
  });
}
