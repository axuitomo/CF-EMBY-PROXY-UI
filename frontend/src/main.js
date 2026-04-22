import { startBankerAdminRuntime } from './banker-runtime-loader';

try {
  await startBankerAdminRuntime();
} catch (error) {
  console.error('banker admin runtime bootstrap failed', error);
}
