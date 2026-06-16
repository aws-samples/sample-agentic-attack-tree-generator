// Route: "/applications/:appId/versions/:versionId/threats/:threatIndex"
//        →  legacy VersionDetailPage
import VersionDetailView from './VersionDetailView.js';

export function generateStaticParams(): Array<{
  appId: string;
  versionId: string;
  threatIndex: string;
}> {
  return [];
}

export default function VersionDetailRoute() {
  return <VersionDetailView />;
}
