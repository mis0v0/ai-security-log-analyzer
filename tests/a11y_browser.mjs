import {constants} from 'node:fs';
import {access, stat} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {chromium} from '@playwright/test';

export async function launchTestChrome() {
  // CI verifies the package. Local runs must provide a verified executable.
  const executablePath = process.env.ASLA_TEST_CHROME;
  if (!executablePath || !isAbsolute(executablePath)) {
    throw new Error('ASLA_TEST_CHROME must be an absolute path to verified Chrome');
  }
  await access(executablePath, constants.X_OK);
  if (!(await stat(executablePath)).isFile()) {
    throw new Error('ASLA_TEST_CHROME must point to a Chrome executable file');
  }
  return chromium.launch({
    executablePath,
    headless: true,
    chromiumSandbox: true,
    args: [
      '--disable-background-networking', '--no-first-run',
      '--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1',
    ],
  });
}
