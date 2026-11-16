import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const credentialNames = [
  'CREDS_KEY',
  'CREDS_IV',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
] as const;

export type CredentialName = (typeof credentialNames)[number];
// 联合类型 CredentialName = 'CREDS_KEY' | 'CREDS_IV' | 'JWT_SECRET' | 'JWT_REFRESH_SECRET'

export type CredentialSource = 'environment' | 'temporary';

export interface CredentialRuntimeState {
  filePath: string;
  sources: Record<CredentialName, CredentialSource>;
  generated: CredentialName[];
  loadedFromFile: CredentialName[];
  missingFromEnvironment: CredentialName[];
  persistenceFailed: boolean;
}

export interface CredentialFingerprintRecord {
  CREDS_KEY: string;
  CREDS_IV: string;
  JWT_SECRET: string;
  JWT_REFRESH_SECRET: string;
}

interface CredentialFileResult {
  values: Partial<Record<CredentialName, string>>;
  exists: boolean;
  readable: boolean;
}

type CredentialFileWriteResult = 'written' | 'exists' | 'failed';

export const credentialMetadataId = 'primary';
export const credentialMetadataCollection = 'librechatCredentialMetadata';

const credentialRuntimeKey = Symbol.for('librechat.credentials.runtime');
const tempCredentialPathEnvironment = 'LIBRECHAT_TEMP_CREDENTIALS_PATH';

const legacyCredentialFingerprints: Partial<Record<CredentialName, string[]>> = {
  CREDS_KEY: [
    '7c1154b5152983978147ea87e4a2066d4768673e9d85d6a792cddc2f784efd2f',
    '6aa4b14dcf6d5094e8f3ed7ac00ba5f0a4d36af50940e870c987a101149a06b3',
  ],
  CREDS_IV: [
    '06d2e911edb4d45985b9d6338ec3d4c6b4bde69f8143437797c187ab07085531',
    'be066640b0c70fcf71e9181eca99768f87da3e4e3764282dfc8063da2f4010ca',
  ],
  JWT_SECRET: ['69024f21e9ad17594dcccd93e87399af24a5426ccfe6108d1787f0335966abc4'],
  JWT_REFRESH_SECRET: ['282ad5f60261639fefed381976b4d0dde52eab5527a1ab2ec75d5be1efa1165b'],
};

const legacyJwtCredentialNames = new Set<CredentialName>(['JWT_SECRET', 'JWT_REFRESH_SECRET']);

function rejectLegacyJwtCredential(name: CredentialName, value: string): void {
  // 如果 name 不是 JWT_SECRET 或者 JWT_REFRESH_SECRET 直接返回

  // 如果 value 是空值，则直接返回；
  // 如果 value 是非空值，则判断其 SHA-256 指纹是否在 legacyCredentialFingerprints 中，如果不在，则直接返回
  if (!legacyJwtCredentialNames.has(name) || !isLegacyCredential(name, value)) {
    return;
  }

  // name 是 JWT_SECRET 或者 JWT_REFRESH_SECRET，并且 value 的 SHA-256 指纹在 legacyCredentialFingerprints 中，抛出错误。
  throw new Error(
    `[credentials] ${name} uses a retired default value. Configure a unique replacement before starting LibreChat.`,
  );
}

// globalThis 是一个全局对象，在 Node.js 中，可以通过它保存当前运行环境内共享的数据，生命周期与运行进程一致
// & 是交叉类型，把两种类型合在一起：
// typeof globalThis & Record<symbol, CredentialRuntimeState | undefined>
// 也就是：保留全局对象原有的类型，同时允许按这里声明的类型访问 Symbol 属性
// const credentialRuntimeKey = Symbol.for('librechat.credentials.runtime');
function getRuntimeState(): CredentialRuntimeState | undefined {
  const runtime = globalThis as typeof globalThis &
    Record<symbol, CredentialRuntimeState | undefined>;
  return runtime[credentialRuntimeKey];
}

function setRuntimeState(state: CredentialRuntimeState): void {
  const runtime = globalThis as typeof globalThis &
    Record<symbol, CredentialRuntimeState | undefined>;
  runtime[credentialRuntimeKey] = state;
}

// .env 没有设置 tempCredentialPathEnvironment 环境变量，所以 CredentialPath 是 process.cwd()/.env.temp
function getCredentialPath(): string {
  const configuredPath = process.env[tempCredentialPathEnvironment]?.trim();
  return path.resolve(configuredPath || path.join(process.cwd(), '.env.temp'));
}

// 输出 {'CREDS_KEY': 'xxxx', 'CREDS_IV': 'xxxx', 'JWT_SECRET': 'xxxx, 'JWT_REFRESH_SECRET': 'xxxx'}
function parseCredentialFile(contents: string): Partial<Record<CredentialName, string>> {
  return contents.split(/\r?\n/).reduce<Partial<Record<CredentialName, string>>>((values, line) => {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (!match || !credentialNames.includes(match[1] as CredentialName)) {
      return values;
    }

    const value = match[2].trim();
    values[match[1] as CredentialName] =
      value.length >= 2 && value.startsWith('"') && value.endsWith('"')
        ? value.slice(1, -1)
        : value;
    return values;
  }, {});
}

// interface CredentialFileResult {
//   values: Partial<Record<CredentialName, string>>;
//   exists: boolean;
//   readable: boolean;
// }
function readCredentialFile(filePath: string): CredentialFileResult {
  try {
    return {
      values: parseCredentialFile(fs.readFileSync(filePath, 'utf8')),
      exists: true,
      readable: true,
    };
  } catch (error) {
    // 文件不存在
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { values: {}, exists: false, readable: true };
    }

    // 文件存在，但无法读取
    console.warn(`[credentials] Unable to read temporary credentials file at ${filePath}.`);
    return { values: {}, exists: true, readable: false };
  }
}

function isConfiguredCredential(value: string | undefined): value is string {
  return Boolean(value?.trim());
}

function isUsableTemporaryCredential(
  name: CredentialName,
  value: string | undefined,
): value is string {
  if (!value?.trim()) {
    return false;
  }

  if (name === 'CREDS_KEY') {
    return /^[0-9a-f]{64}$/i.test(value);
  }

  if (name === 'CREDS_IV') {
    return /^[0-9a-f]{32}$/i.test(value);
  }

  return value.length >= 32;
}

function generateCredential(name: CredentialName): string {
  return crypto.randomBytes(name === 'CREDS_IV' ? 16 : 32).toString('hex');
}

// 判断文件是否是 .env 或者 .env.example
function isProtectedEnvironmentPath(filePath: string): boolean {
  const basename = path.basename(path.resolve(filePath));
  return basename === '.env' || basename === '.env.example';
}

function serializeCredentialFile(values: Partial<Record<CredentialName, string>>): string {
  return [
    '# Automatically generated by LibreChat. Keep this file private and persistent.',
    ...credentialNames.filter((name) => values[name]).map((name) => `${name}=${values[name]}`),
    '',
  ].join('\n');
}

function hasUsableCredentialValues(filePath: string, names: CredentialName[]): boolean {
  const file = readCredentialFile(filePath);
  return (
    file.readable && names.every((name) => isUsableTemporaryCredential(name, file.values[name]))
  );
}

function writeCredentialFile(
  // 原始变量名称：filePath, temporaryValues, file.exists, generated
  // filePath 通常是 process.cwd()/.env.temp
  filePath: string,
  values: Partial<Record<CredentialName, string>>,
  overwrite: boolean,
  generatedNames: CredentialName[],
): CredentialFileWriteResult {
  // 如果 filePath 的文件是 .env 或者 .env.example，则返回 failed
  if (isProtectedEnvironmentPath(filePath)) {
    return 'failed';
  }

  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const lockPath = `${filePath}.lock`;
  let ownsLock = false;
  try {
    // 确保 filePath 文件的父目录存在
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(temporaryPath, serializeCredentialFile(values), { mode: 0o600 });

    // filePath 文件是否存在？
    // filePath 存在
    if (overwrite) {
      try {
        // 为 temporaryPath 创建一个硬链接 lockPath
        fs.linkSync(temporaryPath, lockPath);
        ownsLock = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw error;
        }

        if (hasUsableCredentialValues(lockPath, generatedNames)) {
          try {
            fs.renameSync(lockPath, filePath);
          } catch {
            // The lock owner may have already promoted the same credential values.
          }
        }
        return hasUsableCredentialValues(filePath, generatedNames) ? 'exists' : 'failed';
      }

      // 如果 filePath 可读且已有 generatedNames 对应的值，那么则返回 exists
      if (hasUsableCredentialValues(filePath, generatedNames)) {
        return 'exists';
      }
      fs.renameSync(temporaryPath, filePath);
    } else {
      // filePath 不存在
      try {
        fs.linkSync(temporaryPath, filePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          return 'exists';
        }
        throw error;
      }
    }

    fs.chmodSync(filePath, 0o600);
    return 'written';
  } catch {
    return 'failed';
  } finally {
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // The temporary path is absent after a successful rename.
    }
    if (ownsLock) {
      try {
        fs.unlinkSync(lockPath);
      } catch {
        // A contender may have promoted the lock while adopting its values.
      }
    }
  }
}

function hardenCredentialFile(filePath: string): void {
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    console.warn(`[credentials] Unable to restrict permissions on ${filePath}.`);
  }
}

function adoptCredentialFile(
  filePath: string,
  names: CredentialName[],
  sources: Record<CredentialName, CredentialSource>,
  loadedFromFile: CredentialName[],
): boolean {
  const file = readCredentialFile(filePath);
  if (!file.readable) {
    return false;
  }

  for (const name of names) {
    const value = file.values[name];
    if (!isUsableTemporaryCredential(name, value)) {
      return false;
    }

    rejectLegacyJwtCredential(name, value);
  }

  for (const name of names) {
    process.env[name] = file.values[name];
    sources[name] = 'temporary';
    loadedFromFile.push(name);
  }
  hardenCredentialFile(filePath);
  return true;
}

// 核心函数
export function bootstrapCredentials(): CredentialRuntimeState {
  // export interface CredentialRuntimeState {
  //   filePath: string;
  //   sources: Record<CredentialName, CredentialSource>;
  //   generated: CredentialName[];
  //   loadedFromFile: CredentialName[];
  //   missingFromEnvironment: CredentialName[];
  //   persistenceFailed: boolean;
  // }

  // 读取全局状态，如果已经存在，则返回的类型是 CredentialRuntimeState，否则返回 undefined
  const existingState = getRuntimeState();
  if (existingState) {
    return existingState;
  }

  // getRuntimeState() 返回 undefined，则继续执行下述代码
  // Validate explicit credentials before generating or adopting any missing values.
  // 检查环境变量中是否存在 CREDS_KEY 和 CREDS_IV，如果存在，则检查其长度是否符合要求
  // CREDS_KEY 必须是 64 个十六进制字符，CREDS_IV 必须是 32 个十六进制字符，如果存在但不符合要求，则抛出错误，阻止启动。
  for (const name of ['CREDS_KEY', 'CREDS_IV'] as const) {
    const value = process.env[name];
    // 如果 value 不是空值，但同时 value 的长度不符合要求
    if (isConfiguredCredential(value) && !isUsableTemporaryCredential(name, value)) {
      const bytes = name === 'CREDS_KEY' ? 32 : 16;

      // throw new Error(...) 会立即中断当前执行路径，后面的代码不会继续执行，并将错误沿调用栈向上传递。
      throw new Error(
        `[credentials] ${name} must be exactly ${bytes * 2} hexadecimal characters (${bytes} bytes). ` +
          'Refusing startup to prevent weak encryption or late crypto failures. ' +
          'Restore the original credential if it protects existing data; plan a controlled migration before rotating it.',
      );
    }
  }

  // 环境变量中没有 CREDS_KEY 或者 CREDS_IV，或者它们的长度符合要求

  // filePath = process.cwd()/.env.temp
  const filePath = getCredentialPath();

  // 文件存在，读取正常：return { values: -, exists: true, readable: true }
  // values 是完整的或不完整的 {'CREDS_KEY': 'xxxx', 'CREDS_IV': 'xxxx', 'JWT_SECRET': 'xxxx, 'JWT_REFRESH_SECRET': 'xxxx'}
  // 文件存在，但无法读取：return { values: {}, exists: true, readable: false };
  // 文件不存在：return { values: {}, exists: false, readable: true };
  const file = readCredentialFile(filePath);

  const sources = {} as Record<CredentialName, CredentialSource>;
  const generated: CredentialName[] = [];
  const loadedFromFile: CredentialName[] = [];
  const missingFromEnvironment: CredentialName[] = [];
  const temporaryValues: Partial<Record<CredentialName, string>> = {};

  // export interface CredentialRuntimeState {
  //   filePath: string;
  //   sources: Record<CredentialName, CredentialSource>;
  //   generated: CredentialName[];
  //   loadedFromFile: CredentialName[];
  //   missingFromEnvironment: CredentialName[];
  //   persistenceFailed: boolean;
  // }

  for (const name of credentialNames) {
    const environmentValue = process.env[name];
    // 针对某一个 name，如果非空
    if (isConfiguredCredential(environmentValue)) {
      // 如果 name 是 JWT_SECRET 或者 JWT_REFRESH_SECRET，并且 value 的 SHA-256 指纹在 legacyCredentialFingerprints 中，抛出错误。
      rejectLegacyJwtCredential(name, environmentValue);

      // value 是非空值，而且其 SHA-256 指纹不在 legacyCredentialFingerprints 中，满足条件
      sources[name] = 'environment';
      continue;
    }

    // 环境变量中没有 name 对应的值
    // push() 的作用是：把一个元素添加到数组末尾
    missingFromEnvironment.push(name);

    // 检查之前读取的 .env.temp 文件中是否存在 name 对应的值
    const fileValue = file.values[name];
    // 如果文件中存在 name 对应的值，并且其长度符合要求
    if (isUsableTemporaryCredential(name, fileValue)) {
      // 如果 name 是 JWT_SECRET 或者 JWT_REFRESH_SECRET，并且 value 的 SHA-256 指纹在 legacyCredentialFingerprints 中，抛出错误。
      rejectLegacyJwtCredential(name, fileValue);
      process.env[name] = fileValue;
      sources[name] = 'temporary';
      loadedFromFile.push(name);
      temporaryValues[name] = fileValue;
      continue;
    }

    // 临时文件中没有 name 对应的值，或者其长度不符合要求
    const generatedValue = generateCredential(name);
    process.env[name] = generatedValue;
    sources[name] = 'temporary';
    generated.push(name);
    temporaryValues[name] = generatedValue;
  }

  let persistenceFailed = false;
  // 如果 generated.length > 0 && .env.temp 存在且读取正常或者文件不存在
  if (generated.length > 0 && file.readable) {
    const writeResult = writeCredentialFile(filePath, temporaryValues, file.exists, generated);
    if (writeResult === 'exists') {
      const adopted = adoptCredentialFile(filePath, generated, sources, loadedFromFile);
      if (adopted) {
        generated.length = 0;
      } else {
        persistenceFailed = true;
      }
    } else {
      persistenceFailed = writeResult === 'failed';
    }
  } else if (generated.length > 0) {
    // 如果 generated.length > 0，文件存在但读取不正常
    persistenceFailed = true;
  } else if (loadedFromFile.length > 0) {
    // 如果 generated.length == 0，但是 loadedFromFile.length > 0
    hardenCredentialFile(filePath);
  }

  const state: CredentialRuntimeState = {
    filePath,
    sources,
    generated,
    loadedFromFile,
    missingFromEnvironment,
    persistenceFailed,
  };
  setRuntimeState(state);

  // 打印信息
  if (generated.length > 0 && !persistenceFailed) {
    console.warn(
      `[credentials] Generated temporary credentials for ${generated.join(', ')}. ` +
        `They are stored in ${filePath}; configure permanent values before production use.`,
    );
  } else if (generated.length > 0) {
    console.warn(
      `[credentials] Generated process-local credentials for ${generated.join(', ')}. ` +
        'Configure permanent values before production use.',
    );
  } else if (loadedFromFile.length > 0) {
    console.warn(
      `[credentials] Using temporary credentials from ${filePath} for ${loadedFromFile.join(', ')}. ` +
        'Configure permanent values before production use.',
    );
  }

  if (persistenceFailed) {
    console.warn(
      `[credentials] Could not persist temporary credentials to ${filePath}. ` +
        'The generated values will only remain valid for this process.',
    );
  }

  return state;
}

export function getCredentialRuntimeState(): CredentialRuntimeState | undefined {
  return getRuntimeState();
}

// 将凭据字符串计算成 SHA-256 指纹，用于比较和识别凭据。
// 输入是字符串或 undefined，输出是 64 个十六进制字符组成的字符串。
function fingerprintCredential(value: string | undefined): string {
  return crypto
    .createHash('sha256')
    .update(value ?? '')
    .digest('hex');
}

export function getCredentialFingerprints(
  env: NodeJS.ProcessEnv = process.env,
): CredentialFingerprintRecord {
  return credentialNames.reduce<CredentialFingerprintRecord>((fingerprints, name) => {
    fingerprints[name] = fingerprintCredential(env[name]);
    return fingerprints;
  }, {} as CredentialFingerprintRecord);
}

// 如果 value 是空值，则直接返回 false；
// 如果 value 是非空值，则判断其 SHA-256 指纹是否在 legacyCredentialFingerprints 中，如果在，则返回 true，否则返回 false。
export function isLegacyCredential(name: CredentialName, value: string | undefined): boolean {
  // 如果 value 是空值，则直接返回 false
  if (!value) {
    return false;
  }

  // fingerprintCredential(value) 将凭据字符串计算成 SHA-256 指纹，用于比较和识别凭据。
  return legacyCredentialFingerprints[name]?.includes(fingerprintCredential(value)) ?? false;
}

export function getLegacyCredentialNames(env: NodeJS.ProcessEnv = process.env): CredentialName[] {
  return credentialNames.filter((name) => isLegacyCredential(name, env[name]));
}
