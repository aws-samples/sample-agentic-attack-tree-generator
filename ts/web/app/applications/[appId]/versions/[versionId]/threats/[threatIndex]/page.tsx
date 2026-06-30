// Route: "/applications/:appId/versions/:versionId/threats/:threatIndex"
//        →  legacy VersionDetailPage
import VersionDetailView from './VersionDetailView';

export function generateStaticParams(): Array<{
  appId: string;
  versionId: string;
  threatIndex: string;
}> {
  return [{ appId: '__shell__', versionId: '__shell__', threatIndex: '__shell__' }];
}

export default function VersionDetailRoute() {
  return <VersionDetailView />;
}
