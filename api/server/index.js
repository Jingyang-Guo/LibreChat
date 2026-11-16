// CommonJS 和 ES Modules 是 JavaScript 的两套模块化机制
// CommonJS 使用 require() 导入模块，module.exports 导出模块
// ES Modules 使用 import 导入模块，export 导出模块
// Node.js 默认使用 CommonJS，但可以通过 package.json 中的 "type": "module" 或 .mjs 文件启用 ES Modules

// 同一个模块首次使用 require() 加载时，会执行文件顶层的代码（函数定义之外的代码）
// require() 的返回值是 module.exports 对象

// 加载 .env 中的环境变量至 process.env，同时执行 bootstrapCredentials 函数，将结果加载至进程的缓存中，
// 同一 Node.js 进程中，成功加载的模块会被缓存，其他文件再次 require 同一个模块，通常直接返回缓存的导出值，不会重新执行文件。
require('../config/credentials');

const telemetry = require('./telemetry');
const fs = require('fs');
const path = require('path');
require('module-alias')({ base: path.resolve(__dirname, '..') });
const cors = require('cors');
const axios = require('axios');
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const { logger, runAsSystem } = require('@librechat/data-schemas');
const {
  isEnabled,
  issueCsp,
  apiNotFound,
  createMetrics,
  applyCspNonce,
  createCspPolicy,
  shellCacheHeaders,
  escapeHtmlAttribute,
  ErrorController,
  memoryDiagnostics,
  createSecurityHeaders,
  performStartupChecks,
  handleJsonParseError,
  excludeRumBodyParser,
  GenerationJobManager,
  QUERY_DEVTOOLS_HEADER,
  createStreamServices,
  agentStartupIngressMiddleware,
  agentStartupTelemetryMiddleware,
  initializeFileStorage,
  initializeDeploymentSkills,
  initializeDeploymentPlugins,
  getDeploymentPluginSkills,
  getDeploymentPluginHookCapabilities,
  registerDeploymentPluginHooks,
  hasDeploymentPluginHooks,
  hasDeploymentPluginToolApprovalHooks,
  setPluginHookSource,
  loadToolApprovalHooks,
  maybeInjectQueryDevtoolsBootstrap,
  injectConfiguredFooterBootstrap,
  injectColorModeHandoff,
  readBundledThemeBoot,
  createDeploymentThemeShell,
  preAuthTenantMiddleware,
  requestContextMiddleware,
  registerShutdownTask,
  getRemainingShutdownMs,
  registerBackgroundTaskShutdown,
  configureServerTimeouts,
  createReadinessHandler,
  keyvRedisClient,
  ioredisClient,
  cacheConfig,
  setupGracefulShutdown,
  updateInterfacePermissions,
  configureMessageFilterRegexValidator,
  configureFileConfigRegexEngine,
  configureAgentEventRuntime,
  createAgentEventTerminalHandler,
  createScheduleWriteGate,
  startCodeEnvironmentLifecycleReconciler,
  waitForKeyvRedisClient,
  warnOnUnreachableDeliveryPaths,
  createCodeApiUploadRegistry,
  createRequestSanitizer,
  reportEndpointOverrides,
} = require('@librechat/api');
const { connectDb, indexSync } = require('~/db');
const {
  updateAccessPermissions,
  sweepOrphanedPreviews,
  getRoleByName,
  seedDatabase,
  listAllConfigs,
  recordAuditEntry,
} = require('~/models');
const initializeOAuthReconnectManager = require('./services/initializeOAuthReconnectManager');
const { capabilityContextMiddleware } = require('./middleware/roles/capabilities');
const createValidateImageRequest = require('./middleware/validateImageRequest');
const { initializeGitHubSkillSync } = require('./services/Skills/sync');
const { startSkillDeletionSweep } = require('./services/Skills/deletion');
const { initializeAgentTriggerService } = require('./services/Agents/triggers');
const { resumeAgentEventDetachedAction } = require('./services/Agents/detachedActionResume');
const { initializeScheduleEngine, recordExpiredScheduleApproval } = require('./services/Schedules');
const { jwtLogin, ldapLogin, passportLogin } = require('~/strategies');
const { startExpiredFileSweep } = require('./services/Files/process');
const { checkMigrations } = require('./services/start/migration');
const optionalJwtAuth = require('./middleware/optionalJwtAuth');
const initializeMCPs = require('./services/initializeMCPs');
const { configureSubagentTaskRouting } = require('./services/Endpoints/agents/subagentThreadStore');
const configureSocialLogins = require('./socialLogins');
const createSpaFallback = require('./utils/fallback');
const { getAppConfig, rederiveEndpoints } = require('./services/Config');
const staticCache = require('./utils/staticCache');
const noIndex = require('./middleware/noIndex');
const agentEventMethods = require('~/models');

/** Route admin file-config MIME patterns through a linear-time engine (ReDoS-safe) on upload. */
configureFileConfigRegexEngine();

/** Reject messageFilter PII patterns the RE2 runtime engine cannot compile, at config load. */
configureMessageFilterRegexValidator();

// ----------------------------------------------------------------------------------------------
const { PORT, HOST, ALLOW_SOCIAL_LOGIN, DISABLE_COMPRESSION, TRUST_PROXY } = process.env ?? {};
// 环境变量来源：.env 文件，默认情况下 ALLOW_SOCIAL_LOGIN=false, DISABLE_COMPRESSION=undefined, TRUST_PROXY=1

// Allow PORT=0 to be used for automatic free port assignment
const port = isNaN(Number(PORT)) ? 80 : Number(PORT);
const host = HOST || 'localhost';
const trusted_proxy = Number(TRUST_PROXY) || 1; /* trust first proxy by default */
// ----------------------------------------------------------------------------------------------

const app = express();
app.locals.codeApiUploadRegistry = createCodeApiUploadRegistry();

// 服务器是否已准备好提供服务的状态变量
let serverReady = false;

// 调度引擎是启动中、已启用，还是不可用？
// 下行代码声明 scheduleEngineState 变量的类型为 ScheduleEngineState，该变量只能取值 'starting' | 'armed' | 'unavailable'
/** @type {import('@librechat/api').ScheduleEngineState} */
let scheduleEngineState = 'starting';

const SERVER_NOT_READY_CODE = 'SERVER_NOT_READY';
const CHAT_START_RETRY_AFTER_SECONDS = '1';

// 这段代码是一个 Express 中间件，用于在服务器尚未启动完成时，阻止新的聊天 POST 请求。
const rejectChatStartsUntilReady = (req, res, next) => {
  // 以下任意一个条件成立就进入 if
  // serverReady == true    服务器已就绪，可以继续处理。
  // req.method !== 'POST'  请求不是 POST，可以继续处理。
  // req.path === '/abort'  请求是取消生成操作，可以继续处理。
  if (serverReady || req.method !== 'POST' || req.path === '/abort') {
    return next();
    // return next() 有两个作用：调用 next() 继续处理请求，并通过 return 结束当前函数，避免继续执行下面的拒绝逻辑。
  }

  // 如果不满足上述条件
  res.set('Retry-After', CHAT_START_RETRY_AFTER_SECONDS);
  // res.status(503)：设置响应状态码。
  // .json(...)：将 HTTP 响应发送给发起请求的客户端。
  return res.status(503).json({
    code: SERVER_NOT_READY_CODE,
    error: 'Server is still starting. Please retry shortly.',
  });
};

const rejectScheduleWritesUntilReady = createScheduleWriteGate({
  // getState 是一个函数，调用 getState() 得到 scheduleEngineState
  getState: () => scheduleEngineState,
  retryAfterSeconds: CHAT_START_RETRY_AFTER_SECONDS,
});

const configureGenerationStreams = () => {
  const streamServices = createStreamServices();
  GenerationJobManager.configure({
    ...streamServices,
    cleanupOnComplete: !isEnabled(process.env.STREAM_KEEP_COMPLETED_JOBS),
  });
  GenerationJobManager.setApprovalExpiredHandler(recordExpiredScheduleApproval);
  GenerationJobManager.setAdmissionGuard(agentEventMethods.isAgentTriggerPrincipalActive);
  GenerationJobManager.setTerminalHostActionHandler(
    createAgentEventTerminalHandler(agentEventMethods, {
      resumeDetachedAction: resumeAgentEventDetachedAction,
    }),
  );
  GenerationJobManager.initialize();
  // Stop active generations and close their SSE streams while the HTTP server drains.
  registerShutdownTask(
    'generation job manager prepare',
    () => GenerationJobManager.prepareForShutdown(),
    {
      phase: 'pre-drain',
      priority: 100,
    },
  );
  /** Spend the shutdown budget that is actually left waiting for detached generations to
   *  record their own provider drains, holding back a reserve for the tasks after this one.
   *  Abandoning an unrecorded drain fences the next generation permanently. */
  const destroyGenerationJobManager = () => {
    const remaining = getRemainingShutdownMs();
    return GenerationJobManager.destroy(
      remaining == null
        ? undefined
        : { settlementBudgetMs: Math.max(0, remaining - SHUTDOWN_TEARDOWN_RESERVE_MS) },
    );
  };
  // Tear down stream resources before shared caches and telemetry exporters shut down.
  registerShutdownTask('generation job manager', destroyGenerationJobManager, { priority: 100 });
};

/** Reserved for the shutdown tasks that run after the generation job manager. */
// 关闭服务器时，为后续清理工作预留的时间，单位是毫秒
const SHUTDOWN_TEARDOWN_RESERVE_MS = 10_000;

const startServer = async () => {
  // 等待 Redis 客户端准备好，再继续执行后面的代码。
  await waitForKeyvRedisClient();

  // 监控功能
  // metricsMiddleware：中间件，用来记录 HTTP 请求耗时等指标。
  // metricsRouter：路由，用来向监控系统提供指标数据。
  const { metricsMiddleware, metricsRouter } = createMetrics({
    collectAgentEventActorStorageMetrics: () =>
      runAsSystem(async () => {
        const now = new Date();
        const [receiptMetrics, reconciliationMetrics] = await Promise.all([
          agentEventMethods.getAgentEventActorReceiptStorageMetrics(now),
          agentEventMethods.getAgentEventActorReconciliationStorageMetrics(now),
        ]);
        return {
          ...receiptMetrics,
          pendingReconciliations: reconciliationMetrics.pending,
          oldestPendingAgeSeconds: reconciliationMetrics.oldestPendingAgeSeconds,
        };
      }),
  });
  if (!process.env.METRICS_SECRET) {
    logger.warn('[metrics] METRICS_SECRET is not set - /metrics will return 401 for all requests');
  }

  // 运行环境是否是 Bun，Bun 和 Node.js 一样，都可以运行 JavaScript。
  if (typeof Bun !== 'undefined') {
    axios.defaults.headers.common['Accept-Encoding'] = 'gzip';
  }

  await connectDb();

  logger.info('Connected to MongoDB');

  // 启动一个后台定期检查任务，清理、修复代码执行环境中未完成的操作，Mongoose 是 Node.js 程序操作 MongoDB 数据库的工具库。
  startCodeEnvironmentLifecycleReconciler({ mongoose });

  // 启动搜索索引的后台同步，如果同步失败，就记录错误日志。
  // 它负责检查、同步 MongoDB 中的消息和会话数据到 MeiliSearch 搜索索引，供聊天记录搜索使用。
  indexSync().catch((err) => {
    logger.error('[indexSync] Background sync failed:', err);
  });

  // 关闭 Express 默认添加的 X-Powered-By 响应头。
  // 默认情况下，Express 返回的 HTTP 响应可能包含：X-Powered-By: Express，它告诉客户端：“这个服务使用 Express 框架。
  app.disable('x-powered-by');

  // 这行代码告诉 Express：请求经过代理服务器转发时，应该信任多少层代理提供的信息。
  // 比如部署结构是：用户 → Nginx 代理 → LibreChat，LibreChat 直接连接的是 Nginx，因此它看到的连接来源是 Nginx。用户的真实 IP、最初使用的是 HTTP 还是 HTTPS，通常由代理通过请求头传递。
  // trusted_proxy 默认是数字 1，表示信任距离应用最近的一跳代理，适用于类似“用户 → Nginx → LibreChat”的结构。
  app.set('trust proxy', trusted_proxy);

  /* Registered ahead of every route so health checks carry the headers too. */
  // 这段代码的作用是：启用一个中间件，为后续请求的响应添加安全相关的 HTTP 响应头。
  // 如果成功创建了中间件，就通过 app.use() 注册到 Express。之后经过它的请求，响应中就会添加相应的安全头。
  // 这些响应头是在告诉浏览器应该遵守哪些安全规则。
  const securityHeaders = createSecurityHeaders();
  if (securityHeaders) {
    app.use(securityHeaders);
  }

  if (isEnabled(process.env.TRUST_TENANT_HEADER)) {
    logger.warn(
      '[Security] TRUST_TENANT_HEADER is active. Ensure your reverse proxy strips and sets ' +
        'X-Tenant-Id — untrusted clients must not be able to supply it directly.',
    );
  } else if (isEnabled(process.env.TENANT_ISOLATION_STRICT)) {
    logger.warn(
      '[Security] TENANT_ISOLATION_STRICT is active while TRUST_TENANT_HEADER is disabled. ' +
        'Pre-authentication tenant headers will be ignored.',
    );
  }

  // 这行代码的作用是：在系统上下文中执行数据库基础数据初始化，并等待它完成。
  await runAsSystem(seedDatabase);
  /* Recover stuck `status: 'pending'` records from a crash mid-render.
   * `runAsSystem` is required — `File` is tenant-isolated and strict
   * mode rejects unscoped queries. Lazy sweep in the preview endpoint
   * covers anything younger than the boot cutoff. */
  runAsSystem(sweepOrphanedPreviews).catch((err) => {
    logger.error('[sweepOrphanedPreviews] Background sweep failed:', err);
  });

  // 加载项目根目录的 librechat.yaml 配置
  const appConfig = await getAppConfig({ baseOnly: true });
  await configureSubagentTaskRouting(appConfig?.endpoints?.agents?.subagentActivity);
  registerBackgroundTaskShutdown({
    interruptGraceMs: appConfig?.endpoints?.agents?.backgroundTasks?.shutdownInterruptGraceMs,
  });
  configureAgentEventRuntime(appConfig?.endpoints?.agents?.eventDriven);
  warnOnUnreachableDeliveryPaths(appConfig);
  initializeFileStorage(appConfig);

  const projectRoot = path.resolve(__dirname, '../..');
  // Plugin hooks execute only when the operator opts in via DEPLOYMENT_PLUGIN_HOOKS;
  // without it, declared hook documents load as parsed-but-inert with a warning.
  await initializeDeploymentPlugins({
    projectRoot,
    hookCapabilities: getDeploymentPluginHookCapabilities(),
  });
  // Hand the run seam its plugin-hook source without a packages/api-internal
  // agents -> plugins import (see agents/hooks/source.ts).
  setPluginHookSource({
    hasHooks: hasDeploymentPluginHooks,
    hasToolApprovalHooks: hasDeploymentPluginToolApprovalHooks,
    register: registerDeploymentPluginHooks,
  });
  await initializeDeploymentSkills({
    projectRoot,
    additionalSkills: getDeploymentPluginSkills(),
  });
  initializeGitHubSkillSync(appConfig);
  startSkillDeletionSweep(appConfig.skillDeletion);
  startExpiredFileSweep({ appConfig, loadAppConfig: getAppConfig });
  // Register any programmatic tool-approval policy hooks declared in
  // `endpoints.agents.toolApproval.hooks`. Honor the `enabled` kill switch: when tool
  // approval is off we pass no hooks, so a disabled endpoint imports/runs nothing (and any
  // previously loaded batch is unregistered). Hooks are read from the BASE config only —
  // they register once, process-wide; per-user/tenant differences belong inside the hook
  // (via its context), not in per-override module lists.
  const toolApproval = appConfig?.endpoints?.agents?.toolApproval;
  await loadToolApprovalHooks(toolApproval?.enabled ? toolApproval.hooks : undefined, {
    basePath: path.resolve(__dirname, '../..'),
  });
  await runAsSystem(async () => {
    await performStartupChecks(appConfig);
    await updateInterfacePermissions({
      appConfig,
      getRoleByName,
      updateAccessPermissions,
      recordAuditEntry,
    });
  });

  // 加载路由模块，因为 routes 是一个目录，所以会加载其中的 index.js，路由模块负责定义“什么请求交给什么代码处理”。
  /* Route modules build their rate limiters as they load, so they load only after the
   * startup checks have applied `rateLimits` from librechat.yaml. */
  const routes = require('./routes');

  const indexPath = path.join(appConfig.paths.dist, 'index.html');
  let indexHTML = fs.readFileSync(indexPath, 'utf8');

  // In order to provide support to serving the application in a sub-directory
  // We need to update the base href if the DOMAIN_CLIENT is specified and not the root path
  // 这段代码的作用是：根据网站地址的路径，修改 HTML 的 <base href>，让网站部署在子路径时，浏览器能正确解析相对地址。
  // 例如，你的网站部署在：DOMAIN_CLIENT=https://example.com/chat，它会把 HTML 中的 <base href="/"> 改成 <base href="/chat/"></base>
  if (process.env.DOMAIN_CLIENT) {
    const clientUrl = new URL(process.env.DOMAIN_CLIENT);
    const baseHref = clientUrl.pathname.endsWith('/')
      ? clientUrl.pathname
      : `${clientUrl.pathname}/`;
    if (baseHref !== '/') {
      logger.info(`Setting base href to ${baseHref}`);
      indexHTML = indexHTML.replace(/base href="\/"/, `base href="${baseHref}"`);
    }
  }

  /* The composer lays out against whether a footer bar sits beneath it, and
     `/api/config` answers that only after it has painted. One shell serves every
     request, before there is a caller whose overrides could be resolved, so the
     answer is the deployment's base configuration; `/api/config` resolves the
     caller's and the client prefers it. */
  // 这段代码的作用是：把页脚相关的初始配置写进 HTML，让浏览器第一次显示页面时，就知道该如何安排页脚和输入框的位置。
  indexHTML = injectConfiguredFooterBootstrap(indexHTML, {
    customFooter: process.env.CUSTOM_FOOTER,
    landingFooter: appConfig?.interfaceConfig?.landingFooter,
  });

  indexHTML = injectColorModeHandoff(indexHTML, appConfig.interfaceConfig?.colorModeFromUrl);
  const indexShell = createDeploymentThemeShell(
    indexHTML,
    appConfig.interfaceConfig?.theme,
    readBundledThemeBoot(appConfig.paths.dist),
  );

  const cspPolicy = createCspPolicy();
  const shellCache = shellCacheHeaders(cspPolicy != null);

  // 发送 IndexHtml
  const sendIndexHtml = (req, res) => {
    res.set(shellCache);
    res.vary(QUERY_DEVTOOLS_HEADER);

    const lang = req.cookies.lang || req.headers['accept-language']?.split(',')[0] || 'en-US';
    const saneLang = escapeHtmlAttribute(lang);
    let updatedIndexHtml = indexShell(req, res).replace(
      /lang="en-US"/g,
      () => `lang="${saneLang}"`,
    );
    updatedIndexHtml = maybeInjectQueryDevtoolsBootstrap(updatedIndexHtml, req);

    /* Nonce last: every injected script above must be stamped too. */
    if (cspPolicy) {
      const csp = issueCsp(cspPolicy);
      res.set(csp.headerName, csp.headerValue);
      updatedIndexHtml = applyCspNonce(updatedIndexHtml, csp.nonce);
    }

    res.type('html');
    res.send(updatedIndexHtml);
  };

  app.get('/health', (_req, res) => res.status(200).send('OK'));
  app.get('/livez', (_req, res) => res.status(200).send('OK'));
  app.get(
    '/readyz',
    createReadinessHandler(() => serverReady, {
      useRedis: cacheConfig.USE_REDIS,
      ioredis: ioredisClient,
      keyv: keyvRedisClient,
    }),
  );

  /* Middleware */
  app.use(requestContextMiddleware);
  app.use('/api/agents/chat', agentStartupIngressMiddleware);
  app.use(metricsMiddleware);
  app.use(noIndex);
  app.use(excludeRumBodyParser(express.json({ limit: '3mb' })));
  app.use(excludeRumBodyParser(express.urlencoded({ extended: true, limit: '3mb' })));
  app.use(handleJsonParseError);

  /**
   * Express 5 Compatibility: Make req.query writable for mongoSanitize
   * In Express 5, req.query is read-only by default, but express-mongo-sanitize needs to modify it
   */
  app.use((req, _res, next) => {
    Object.defineProperty(req, 'query', {
      ...Object.getOwnPropertyDescriptor(req, 'query'),
      value: req.query,
      writable: true,
    });
    next();
  });

  app.use(createRequestSanitizer(mongoSanitize));
  app.use(cors());
  app.use(cookieParser());

  if (!isEnabled(DISABLE_COMPRESSION)) {
    app.use(compression());
  } else {
    console.warn('Response compression has been disabled via DISABLE_COMPRESSION.');
  }

  app.get('/index.html', sendIndexHtml);
  app.use(staticCache(appConfig.paths.dist));
  app.use(staticCache(appConfig.paths.fonts));
  app.use(staticCache(appConfig.paths.assets));

  if (telemetry.enabled) {
    app.use(telemetry.telemetryMiddleware);
  }
  app.use('/api/agents/chat', agentStartupTelemetryMiddleware);

  if (!ALLOW_SOCIAL_LOGIN) {
    console.warn('Social logins are disabled. Set ALLOW_SOCIAL_LOGIN=true to enable them.');
  }

  /* OAUTH */
  app.use(passport.initialize());
  passport.use(jwtLogin());
  passport.use(passportLogin());

  /* LDAP Auth */
  if (process.env.LDAP_URL && process.env.LDAP_USER_SEARCH_BASE) {
    passport.use(ldapLogin);
  }

  if (isEnabled(ALLOW_SOCIAL_LOGIN)) {
    await configureSocialLogins(app, appConfig);
  }

  /* Per-request capability cache — must be registered before any route that calls hasCapability */
  app.use(capabilityContextMiddleware);

  /* Pre-auth tenant context for unauthenticated routes that need tenant scoping.
   * The reverse proxy / auth gateway sets `X-Tenant-Id` header for multi-tenant deployments. */
  app.use('/oauth', preAuthTenantMiddleware, routes.oauth);
  /* API Endpoints */
  app.use('/api/auth', preAuthTenantMiddleware, routes.auth);
  app.use('/api/insights', routes.insights);
  app.use('/api/admin', routes.adminAuth);
  app.use('/api/admin/config', routes.adminConfig);
  app.use('/api/admin/code-environments', routes.adminCodeEnvironments);
  app.use('/api/code-environments', routes.codeEnvironments);
  app.use('/api/admin/langfuse', routes.adminLangfuse);
  app.use('/api/admin/grants', routes.adminGrants);
  app.use('/api/admin/groups', routes.adminGroups);
  app.use('/api/admin/roles', routes.adminRoles);
  app.use('/api/admin/skills', routes.adminSkills);
  app.use('/api/admin/users', routes.adminUsers);
  app.use('/api/admin/audit-log', routes.adminAuditLog);
  app.use('/api/actions', routes.actions);
  app.use('/api/keys', routes.keys);
  app.use('/api/api-keys', routes.apiKeys);
  app.use('/api/user', routes.user);
  app.use('/api/search', routes.search);
  app.use('/api/messages', routes.messages);
  app.use('/api/convos', routes.convos);
  app.use('/api/pull-requests', preAuthTenantMiddleware, routes.pullRequests);
  app.use('/api/traces', routes.traces);
  app.use('/api/presets', routes.presets);
  app.use('/api/projects', routes.projects);
  app.use('/api/prompts', routes.prompts);
  app.use('/api/skills', routes.skills);
  app.use('/api/categories', routes.categories);
  app.use('/api/endpoints', routes.endpoints);
  app.use('/api/balance', routes.balance);
  app.use('/api/models', routes.models);
  app.use('/api/config', preAuthTenantMiddleware, optionalJwtAuth, routes.config);
  app.use('/api/assistants', routes.assistants);
  app.use('/api/files', await routes.files.initialize());
  app.use(
    '/images/',
    createValidateImageRequest({
      secureImageLinks: appConfig.secureImageLinks,
    }),
    routes.staticRoute,
  );
  app.use('/api/share', preAuthTenantMiddleware, routes.share);
  app.use('/api/roles', routes.roles);
  app.use('/api/agents/chat', rejectChatStartsUntilReady);
  app.use('/api/agents', routes.agents);
  app.use('/api/banner', routes.banner);
  app.use('/api/memories', routes.memories);
  app.use('/api/schedules', rejectScheduleWritesUntilReady, routes.schedules);
  app.use('/api/permissions', routes.accessPermissions);

  app.use('/api/tags', routes.tags);
  app.use('/api/mcp', routes.mcp);
  app.use('/api/rum', routes.rum);

  app.use('/metrics', metricsRouter);

  app.use('/api', routes.openapi);

  /** 404 for unmatched API routes */
  app.use('/api', apiNotFound);

  /** SPA fallback - serve index.html for all unmatched routes */
  // 兜底路由
  // http://服务器IP地址
  app.use(createSpaFallback(sendIndexHtml));

  /** Record trace errors before the final error controller. */
  if (telemetry.enabled) {
    app.use(telemetry.telemetryErrorMiddleware);
  }
  /** Error handler (must be last - Express identifies error middleware by its 4-arg signature) */
  app.use(ErrorController);

  configureGenerationStreams();

  const server = app.listen(port, host, async (err) => {
    if (err) {
      logger.error('Failed to start server:', err);
      process.exit(1);
    }

    if (host === '0.0.0.0') {
      logger.info(
        `Server listening on all interfaces at port ${port}. Use http://localhost:${port} to access it`,
      );
    } else {
      logger.info(`Server listening at http://${host == '0.0.0.0' ? 'localhost' : host}:${port}`);
    }

    /**
     * The listen callback is async, so any rejection from these awaits would
     * otherwise be detached from `startServer().catch(...)` (which only
     * catches errors that happen before `app.listen`). Without explicit
     * handling, the global `unhandledRejection` handler would swallow init
     * failures and leave the server listening but only partially
     * initialized — passing liveness checks while serving broken requests.
     */
    try {
      await runAsSystem(async () => {
        await initializeMCPs();
        await initializeOAuthReconnectManager();
      });
      /** Logs only, so readiness never waits on reading every config document. */
      reportEndpointOverrides({
        listConfigs: () => runAsSystem(() => listAllConfigs()),
        baseYaml: appConfig?.config ?? {},
        rederiveEndpoints,
      }).catch((err) => {
        logger.error('[config] Failed to report endpoint overrides:', err);
      });
      await checkMigrations();

      const inspectFlags = process.execArgv.some((arg) => arg.startsWith('--inspect'));
      if (inspectFlags || isEnabled(process.env.MEM_DIAG)) {
        memoryDiagnostics.start();
      }
      await initializeAgentTriggerService({
        address: server.address(),
        completionResultBatchSize:
          appConfig?.endpoints?.agents?.backgroundTasks?.completionResultBatchSize,
        completionReceiptBatching:
          appConfig?.endpoints?.agents?.backgroundTasks?.completionReceiptBatching,
        deadLetterRetentionDays: appConfig?.endpoints?.agents?.eventDriven?.deadLetterRetentionDays,
        idlePolling: appConfig?.endpoints?.agents?.eventDriven?.idlePolling,
      });
      const scheduleEngineArmed = (await initializeScheduleEngine()) != null;
      scheduleEngineState = scheduleEngineArmed ? 'armed' : 'unavailable';
      if (!scheduleEngineArmed) {
        // Terminal, not transient: arming is attempted once, so schedule writes are refused
        // for the life of this process. Logged at error level because the only other signal
        // an operator gets is a 503 on every write — every other health signal stays green.
        logger.error(
          '[schedules] write routes are PERMANENTLY unavailable in this process: the engine did not arm. ' +
            'Resolve the cause logged above and restart.',
        );
      }
      serverReady = true;
      logger.info('Server readiness checks passing.');
    } catch (initErr) {
      serverReady = false;
      logger.error('Post-listen initialization failed:', initErr);
      process.exit(1);
    }
  });

  configureServerTimeouts(server);
  logger.info('HTTP server timeout configuration', {
    keepAliveTimeout: server.keepAliveTimeout,
    keepAliveTimeoutBuffer: server.keepAliveTimeoutBuffer,
    headersTimeout: server.headersTimeout,
    requestTimeout: server.requestTimeout,
  });

  setupGracefulShutdown(server);
};

/**
 * Boot rejections (e.g. `connectDb`, `getAppConfig`, `performStartupChecks`)
 * must remain fail-fast: a half-initialized process with no listening HTTP
 * server should die immediately so the orchestrator restarts it, instead of
 * being kept alive by the `unhandledRejection` handler below until the
 * liveness probe eventually times out. Mirrors the pattern in
 * `experimental.js`.
 */
startServer().catch((err) => {
  logger.error('Failed to start server:', err);
  process.exit(1);
});

let messageCount = 0;
process.on('uncaughtException', (err) => {
  if (!err.message.includes('fetch failed')) {
    logger.error('There was an uncaught error:', err);
  }

  if (err.message && err.message?.toLowerCase()?.includes('abort')) {
    logger.warn('There was an uncatchable abort error.');
    return;
  }

  if (err.message.includes('GoogleGenerativeAI')) {
    logger.warn(
      '\n\n`GoogleGenerativeAI` errors cannot be caught due to an upstream issue, see: https://github.com/google-gemini/generative-ai-js/issues/303',
    );
    return;
  }

  if (err.message.includes('fetch failed')) {
    if (messageCount === 0) {
      logger.warn('Meilisearch error, search will be disabled');
      messageCount++;
    }

    return;
  }

  if (err.message.includes('OpenAIError') || err.message.includes('ChatCompletionMessage')) {
    logger.error(
      '\n\nAn Uncaught `OpenAIError` error may be due to your reverse-proxy setup or stream configuration, or a bug in the `openai` node package.',
    );
    return;
  }

  if (err.stack && err.stack.includes('@librechat/agents')) {
    logger.error(
      '\n\nAn error occurred in the agents system. The error has been logged and the app will continue running.',
      {
        message: err.message,
        stack: err.stack,
      },
    );
    return;
  }

  if (isEnabled(process.env.CONTINUE_ON_UNCAUGHT_EXCEPTION)) {
    logger.error('Unhandled error encountered. The app will continue running.', {
      name: err?.name,
      message: err?.message,
      stack: err?.stack,
    });
    return;
  }

  process.exit(1);
});

/**
 * Unhandled promise rejection handler.
 *
 * Node 15+ terminates the process by default when a promise rejection is
 * unhandled. MCP OAuth reconnect storms and streamable-HTTP transport resets
 * can produce transient fire-and-forget rejections (ECONNRESET, token refresh
 * races) that are recoverable — the server should log and keep serving other
 * requests rather than silently crash under load.
 *
 * Non-Error reasons are forwarded as-is so structured payloads (e.g.
 * `{ code: "ECONNRESET", errno: -104 }`) survive instead of being collapsed to
 * "[object Object]" by `String()`.
 */
process.on('unhandledRejection', (reason) => {
  if (reason instanceof Error) {
    logger.error('Unhandled promise rejection. The app will continue running.', {
      name: reason.name,
      message: reason.message,
      stack: reason.stack,
      cause: reason.cause,
    });
    return;
  }
  logger.error('Unhandled promise rejection. The app will continue running.', { reason });
});

/** Export app for easier testing purposes */
module.exports = app;
