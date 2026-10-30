import RunLogsView from './RunLogsView';

export function generateStaticParams(): Array<{ appId: string; versionId: string }> {
  return [{ appId: '__shell__', versionId: '__shell__' }];
}

export default function RunLogsRoute() {
  return <RunLogsView />;
}
