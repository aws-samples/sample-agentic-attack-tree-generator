import JSZip from 'jszip';

export type DirectoryFile = File;

function relativePath(file: DirectoryFile): string {
  const candidate = (file.webkitRelativePath || file.name).replaceAll('\\', '/');
  const segments = candidate.split('/').filter(Boolean);
  if (
    segments.length === 0 ||
    segments.some((segment) => segment === '.' || segment === '..' || segment.includes('\0'))
  ) {
    throw new Error(`Directory selection contains an invalid path for ${file.name}.`);
  }
  return segments.join('/');
}

export function directoryFileKey(file: DirectoryFile): string {
  return `${relativePath(file)}:${file.size}:${file.lastModified}`;
}

export async function archiveDirectoryFiles(files: readonly DirectoryFile[]): Promise<File> {
  if (files.length === 0) {
    throw new Error('Select a directory before creating its archive.');
  }

  const zip = new JSZip();
  const entries = files
    .map((file) => ({ file, path: relativePath(file) }))
    .sort((left, right) => left.path.localeCompare(right.path));
  for (const { file, path } of entries) {
    zip.file(path, file, {
      binary: true,
      createFolders: false,
      date: new Date(file.lastModified || 0),
    });
  }

  const roots = new Set(entries.map(({ path }) => path.split('/')[0]!));
  const singleRoot = roots.size === 1 ? [...roots][0]! : 'project-directories';
  const safeRoot =
    singleRoot.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[.-]+|[.-]+$/g, '') ||
    'project-directory';
  const blob = await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
    platform: 'UNIX',
  });
  return new File([blob], `${safeRoot}.zip`, {
    type: 'application/zip',
    lastModified: Math.max(...files.map((file) => file.lastModified || 0)),
  });
}
