import { main } from './main.js';

main().catch((error: unknown) => {
  console.error(
    JSON.stringify({
      level: 'error',
      event: 'runtime_start_failed',
      message: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
});
