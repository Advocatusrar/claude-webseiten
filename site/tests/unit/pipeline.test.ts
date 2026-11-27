// Release rules of the pipeline (.github/workflows/ci-cd.yml, decisions in docs/ci-cd.md):
// who may publish and deploy, permissions, the SITE_URL guard, CHECK_LIVE, pinned actions
// and the digest placeholder in deploy/.env.example. The workflow is read as text with the
// small reader from pipeline-hilfen.ts, and its conditions are evaluated over a matrix of
// events, refs, actors and repository variables.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  calledFunctions,
  evaluate,
  guardExitCode,
  interpolate,
  parseYaml,
  runs,
  type ExprContext,
  type YamlValue,
} from './pipeline-hilfen';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');

type YamlMap = { [key: string]: YamlValue };

function map(value: YamlValue | undefined, where: string): YamlMap {
  if (value === null || value === undefined || typeof value === 'string' || Array.isArray(value)) {
    throw new Error(`${where} is not a mapping`);
  }
  return value;
}

function list(value: YamlValue | undefined, where: string): YamlValue[] {
  if (!Array.isArray(value)) throw new Error(`${where} is not a list`);
  return value;
}

function text(value: YamlValue | undefined, where: string): string {
  if (typeof value !== 'string') throw new Error(`${where} is not a text value`);
  return value;
}

function optionalText(value: YamlValue | undefined, where: string): string | undefined {
  return value === undefined || value === null ? undefined : text(value, where);
}

const workflow = map(parseYaml(read('.github/workflows/ci-cd.yml')), 'workflow');
const jobs = map(workflow.jobs, 'jobs');
const job = (name: string): YamlMap => map(jobs[name], `jobs.${name}`);
const steps = (name: string): YamlMap[] =>
  list(job(name).steps, `jobs.${name}.steps`).map((step, i) => map(step, `jobs.${name}.steps[${i}]`));
const needs = (name: string): string[] => {
  const value = job(name).needs;
  if (value === undefined || value === null) return [];
  if (typeof value === 'string') return [value];
  return list(value, `jobs.${name}.needs`).map((n) => text(n, `jobs.${name}.needs`));
};
const jobIf = (name: string): string | undefined => optionalText(job(name).if, `jobs.${name}.if`);

// ---------------------------------------------------------------------------------------
// Scenarios

interface Scenario {
  event: string;
  ref: string;
  actor: string;
  publish?: string;
  deploy?: string;
  siteUrl?: string;
}

const SUCCEEDED = { success: true, failure: false, cancelled: false };
const FAILED = { success: false, failure: true, cancelled: false };
const SKIPPED = { success: false, failure: false, cancelled: false };

function vars(s: Scenario): Record<string, string> {
  const result: Record<string, string> = {};
  if (s.publish !== undefined) result.PUBLISH_ENABLED = s.publish;
  if (s.deploy !== undefined) result.DEPLOY_ENABLED = s.deploy;
  if (s.siteUrl !== undefined) result.SITE_URL = s.siteUrl;
  return result;
}

/** Context of jobs.<id>.if and of the workflow env: no env context. */
function jobContext(s: Scenario, status = SUCCEEDED): ExprContext {
  return { github: { event_name: s.event, ref: s.ref, actor: s.actor }, vars: vars(s), status };
}

/**
 * Adds an env entry that is computed on first access. Entries no condition reads are never
 * evaluated, so a new env value with contexts the scenarios do not model (github.sha,
 * secrets.X, needs.*) does not break the tests; a condition that reads it still fails loudly.
 * Never spread or list these objects (that would compute every entry).
 */
function defineLazy(target: Record<string, string>, name: string, compute: () => string): void {
  let cached: string | undefined;
  Object.defineProperty(target, name, {
    enumerable: true,
    configurable: true,
    get: () => (cached ??= compute()),
  });
}

/** The workflow env as GitHub computes it for a scenario (values are text, computed lazily). */
function workflowEnv(s: Scenario): Record<string, string> {
  const ctx = jobContext(s);
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(map(workflow.env, 'env'))) {
    defineLazy(result, name, () => interpolate(text(value, `env.${name}`), ctx));
  }
  return result;
}

/** Context of a step: workflow env, then job env, then step env (each layer lazy). */
function stepContext(s: Scenario, jobName: string, step?: YamlMap): ExprContext {
  const ctx = jobContext(s);
  let env = workflowEnv(s);
  for (const extra of [job(jobName).env, step?.env]) {
    if (extra === undefined || extra === null) continue;
    const previous = env;
    const layer: Record<string, string> = {};
    for (const name of Object.keys(previous)) defineLazy(layer, name, () => previous[name]);
    for (const [name, value] of Object.entries(map(extra, 'env'))) {
      defineLazy(layer, name, () => interpolate(text(value, `env.${name}`), { ...ctx, env: previous }));
    }
    env = layer;
  }
  return { ...ctx, env };
}

const releaseEnv = (s: Scenario): string => workflowEnv(s).RELEASE;
const publishRuns = (s: Scenario, needsStatus = SUCCEEDED): boolean =>
  runs(jobIf('publish'), jobContext(s, needsStatus));
const deployRuns = (s: Scenario): boolean => runs(jobIf('deploy'), jobContext(s, publishRuns(s) ? SUCCEEDED : SKIPPED));

/** Expected by the operator: push or manual start on main, not by Dependabot, one switch on. */
function shouldRelease(s: Scenario): boolean {
  return (
    (s.event === 'push' || s.event === 'workflow_dispatch') &&
    s.ref === 'refs/heads/main' &&
    s.actor !== 'dependabot[bot]' &&
    (s.publish === 'true' || s.deploy === 'true')
  );
}

const shouldDeploy = (s: Scenario): boolean => shouldRelease(s) && s.deploy === 'true';

const EVENTS = [
  'push',
  'workflow_dispatch',
  'pull_request',
  'pull_request_target',
  'merge_group',
  'schedule',
  'workflow_run',
  'repository_dispatch',
  'release',
];
const REFS = [
  'refs/heads/main',
  'refs/heads/main-alt',
  'refs/heads/feature/neuer-artikel',
  'refs/heads/staging',
  'refs/heads/dependabot/npm_and_yarn/site/astro-7.4.13',
  'refs/heads/gh-readonly-queue/main/pr-7-0123abc',
  'refs/pull/7/merge',
  'refs/tags/v1.0.0',
];
const ACTORS = ['maintainer-example', 'dependabot[bot]', 'github-actions[bot]', 'renovate[bot]'];
const SWITCHES = [undefined, '', 'true', 'false', '1', 'yes'];

const MATRIX: Scenario[] = [];
for (const event of EVENTS)
  for (const ref of REFS)
    for (const actor of ACTORS)
      for (const publish of SWITCHES)
        for (const deploy of SWITCHES) MATRIX.push({ event, ref, actor, publish, deploy });

const show = (value: string | undefined): string => (value === undefined ? '(unset)' : `'${value}'`);
const describeScenario = (s: Scenario): string =>
  `${s.event} ${s.ref} by ${s.actor}, PUBLISH_ENABLED=${show(s.publish)}, DEPLOY_ENABLED=${show(s.deploy)}` +
  (s.siteUrl === undefined && !('siteUrl' in s) ? '' : `, SITE_URL=${show(s.siteUrl)}`);

/** Lists the scenarios where got differs from expected (count and the first ten). */
function mismatches(
  scenarios: Scenario[],
  got: (s: Scenario) => unknown,
  expected: (s: Scenario) => unknown,
): { count: number; first: string[] } {
  const wrong = scenarios.filter((s) => got(s) !== expected(s));
  return {
    count: wrong.length,
    first: wrong.slice(0, 10).map((s) => `${describeScenario(s)}: got ${String(got(s))}`),
  };
}

const NONE = { count: 0, first: [] };

// One dimension changed against a release on main.
const BASE: Scenario = {
  event: 'push',
  ref: 'refs/heads/main',
  actor: 'maintainer-example',
  publish: 'true',
  deploy: 'true',
};

// ---------------------------------------------------------------------------------------

describe('test helpers', () => {
  it('read mappings, lists, flow lists, block text, quotes and comments', () => {
    const yaml = [
      '# comment',
      'top:',
      "  quoted: 'it''s' # trailing comment",
      '  plain: a # b',
      '  list: [one, two]',
      '  empty:',
      '  steps:',
      '    - name: first',
      '      run: |',
      '        echo "# not a comment"',
      '        exit 1',
      '    - uses: owner/repo@abc # v1',
      '  same-indent-list:',
      '  - x',
    ].join('\n');
    expect(parseYaml(yaml)).toEqual({
      top: {
        quoted: "it's",
        plain: 'a',
        list: ['one', 'two'],
        empty: null,
        steps: [{ name: 'first', run: 'echo "# not a comment"\nexit 1\n' }, { uses: 'owner/repo@abc' }],
        'same-indent-list': ['x'],
      },
    });
  });

  it('refuse YAML outside the supported subset instead of guessing', () => {
    expect(() => parseYaml('a:\n\tb: 1')).toThrow(/tab/);
    expect(() => parseYaml('a: {b: 1}')).toThrow(/unsupported/);
    expect(() => parseYaml('a: 1\na: 2')).toThrow(/duplicate/);
    expect(() => parseYaml('a: &anchor 1')).toThrow(/unsupported/);
  });

  it('evaluate expressions like GitHub: case-insensitive strings, operands from && and ||, unset vars', () => {
    const ctx: ExprContext = { github: { ref: 'refs/heads/main' }, vars: { ON: 'true' }, env: { RELEASE: 'false' } };
    expect(evaluate("'ABC' == 'abc'", ctx)).toBe(true);
    expect(evaluate("github.ref != 'refs/heads/main'", ctx)).toBe(false);
    expect(evaluate("vars.UNSET == ''", ctx)).toBe(true);
    expect(evaluate("vars.ON == 'true' && '1' || '0'", ctx)).toBe('1');
    expect(evaluate("env.RELEASE == 'true' && '1' || '0'", ctx)).toBe('0');
    expect(evaluate("vars.UNSET && 'x'", ctx)).toBe('');
    expect(evaluate('true || false && false', ctx)).toBe(true);
    expect(evaluate('(true || false) && false', ctx)).toBe(false);
    expect(evaluate("!(vars.ON == 'true')", ctx)).toBe(false);
    expect(evaluate("true == 'true'", ctx)).toBe(false);
    expect(interpolate("a-${{ vars.ON }}-${{ vars.UNSET == '' }}", ctx)).toBe('a-true-true');
  });

  it('fail loudly on contexts, properties and functions the scenarios do not model', () => {
    const ctx: ExprContext = { github: {}, vars: {} };
    expect(() => evaluate("github.triggering_actor == 'x'", ctx)).toThrow(/not modelled/);
    expect(() => evaluate("env.RELEASE == 'true'", ctx)).toThrow(/env context missing/);
    expect(() => evaluate("startsWith(github.ref, 'refs/heads/')", ctx)).toThrow(/not modelled/);
    expect(() => evaluate("inputs.x == 'y'", ctx)).toThrow(/not modelled/);
    expect(() => evaluate("github.ref >= 'a'", ctx)).toThrow(/unsupported/);
    expect(calledFunctions("always() && !cancelled() && vars.X == 'y'")).toEqual(['always', 'cancelled']);
  });

  it('read guard scripts like bash: exact string comparison, || and && from left to right', () => {
    const guard = (condition: string): string => `if ${condition}; then\n  echo "stop $X"\n  exit 3\nfi\n`;
    const env = { X: 'Main', Y: 'b' };
    expect(guardExitCode(guard('[ "$X" != "main" ]'), env)).toBe(3);
    expect(guardExitCode(guard('[ "$X" = "Main" ]'), env)).toBe(3);
    expect(guardExitCode(guard('[ "$X" = "main" ]'), env)).toBe(0);
    expect(guardExitCode(guard('[ "$X" != "Main" ]'), env)).toBe(0);
    expect(guardExitCode(guard('[ "${X,,}" != "main" ]'), env)).toBe(0);
    expect(guardExitCode(guard('[ "${X^^}" == \'MAIN\' ]'), env)).toBe(3);
    expect(guardExitCode(guard('[ "$X" = "main" ] || [ "$Y" = "b" ]'), env)).toBe(3);
    expect(guardExitCode(guard('[ "$X" = "Main" ] && [ "$Y" = "c" ]'), env)).toBe(0);
    expect(guardExitCode(guard('false || true'), env)).toBe(3);
    expect(guardExitCode(guard('! [ "$UNSET" = "" ]'), env)).toBe(0);
  });

  it('refuse guard scripts outside the supported form instead of running them', () => {
    const guard = (condition: string, body = 'exit 1'): string => `if ${condition}; then\n  ${body}\nfi\n`;
    expect(() => guardExitCode(guard('[[ $X == main ]]'), {})).toThrow(/unquoted|unsupported/);
    expect(() => guardExitCode(guard('[ $X = main ]'), {})).toThrow(/unquoted/);
    expect(() => guardExitCode(guard('[ "$(id -u)" = 0 ]'), {})).toThrow(/unsupported/);
    expect(() => guardExitCode(guard('[ "$X" = dependabot[bot] ]'), {})).toThrow(/glob/);
    expect(() => guardExitCode(guard('true', 'docker push x'), {})).toThrow(/unsupported command/);
    expect(() => guardExitCode(guard('true', 'echo no exit'), {})).toThrow(/no exit/);
    expect(() => guardExitCode('docker push x\n', {})).toThrow(/form/);
  });

  it('add the implicit success() to conditions without a status function', () => {
    const ctx = (status: typeof SUCCEEDED): ExprContext => ({ github: {}, vars: {}, status });
    expect(runs("'x' == 'x'", ctx(SUCCEEDED))).toBe(true);
    expect(runs("'x' == 'x'", ctx(SKIPPED))).toBe(false);
    expect(runs(undefined, ctx(FAILED))).toBe(false);
    expect(runs('always()', ctx(SKIPPED))).toBe(true);
    expect(runs('failure()', ctx(FAILED))).toBe(true);
  });
});

describe('release condition: only push or manual start on main, never Dependabot, one switch on', () => {
  const cases: [string, Scenario, boolean][] = [
    ['push to main with PUBLISH_ENABLED only', { ...BASE, deploy: undefined }, true],
    ['push to main with DEPLOY_ENABLED only', { ...BASE, publish: undefined }, true],
    ['push to main with both switches', BASE, true],
    [
      'manual start on main with PUBLISH_ENABLED only',
      { ...BASE, event: 'workflow_dispatch', deploy: undefined },
      true,
    ],
    [
      'manual start on main with DEPLOY_ENABLED only',
      { ...BASE, event: 'workflow_dispatch', publish: undefined },
      true,
    ],
    ['push to main with both switches unset', { ...BASE, publish: undefined, deploy: undefined }, false],
    ['push to main with both switches "false"', { ...BASE, publish: 'false', deploy: 'false' }, false],
    ['push to main with switches "yes" and "1"', { ...BASE, publish: 'yes', deploy: '1' }, false],
    ['pull request (even with ref main)', { ...BASE, event: 'pull_request' }, false],
    ['pull_request_target (ref is the base branch main)', { ...BASE, event: 'pull_request_target' }, false],
    ['merge queue', { ...BASE, event: 'merge_group' }, false],
    ['schedule (runs on the default branch main)', { ...BASE, event: 'schedule' }, false],
    ['workflow_run', { ...BASE, event: 'workflow_run' }, false],
    ['push to main by dependabot[bot]', { ...BASE, actor: 'dependabot[bot]' }, false],
    ['manual start by dependabot[bot]', { ...BASE, event: 'workflow_dispatch', actor: 'dependabot[bot]' }, false],
    ['push to another branch', { ...BASE, ref: 'refs/heads/feature/neuer-artikel' }, false],
    ['push to a branch that starts with main', { ...BASE, ref: 'refs/heads/main-alt' }, false],
    [
      'manual start on another branch',
      { ...BASE, event: 'workflow_dispatch', ref: 'refs/heads/feature/neuer-artikel' },
      false,
    ],
    ['tag push', { ...BASE, ref: 'refs/tags/v1.0.0' }, false],
  ];

  const rows = cases.map(([name, scenario, expected]) => [name, expected, scenario] as const);
  it.each(rows)('%s -> release %s (RELEASE and publish job)', (_, expected, scenario) => {
    expect(releaseEnv(scenario)).toBe(String(expected));
    expect(publishRuns(scenario)).toBe(expected);
  });

  it('RELEASE matches the decision in every scenario of the matrix', () => {
    expect(mismatches(MATRIX, (s) => releaseEnv(s) === 'true', shouldRelease)).toEqual(NONE);
    expect(MATRIX.some(shouldRelease) && !MATRIX.every(shouldRelease)).toBe(true);
  });

  it('the publish job runs exactly in the scenarios of the decision', () => {
    expect(mismatches(MATRIX, (s) => publishRuns(s), shouldRelease)).toEqual(NONE);
  });
});

describe('RELEASE and the condition of the publish job stay equivalent', () => {
  const variants: Scenario[] = [
    { ...BASE, actor: 'Dependabot[bot]' },
    { ...BASE, publish: 'TRUE', deploy: undefined },
    { ...BASE, publish: undefined, deploy: 'True' },
    { ...BASE, event: 'PUSH' },
  ];

  it('agree on every scenario, also on unusual spellings', () => {
    const all = [...MATRIX, ...variants];
    expect(mismatches(all, (s) => releaseEnv(s) === 'true', publishRuns)).toEqual(NONE);
    const values = new Set(all.map(releaseEnv));
    expect([...values].sort()).toEqual(['false', 'true']);
  });
});

describe('deploy job', () => {
  it('needs the publish job', () => {
    expect(needs('deploy')).toContain('publish');
  });

  it('runs in the environment production', () => {
    const environment = job('deploy').environment;
    const name =
      typeof environment === 'string'
        ? environment
        : text(map(environment, 'jobs.deploy.environment').name, 'environment.name');
    expect(name).toBe('production');
  });

  it('is never allowed to run unless DEPLOY_ENABLED is "true", even when publish succeeded', () => {
    const offDeploy = MATRIX.filter((s) => s.deploy !== 'true');
    expect(
      mismatches(
        offDeploy,
        (s) => runs(jobIf('deploy'), jobContext(s, SUCCEEDED)),
        () => false,
      ),
    ).toEqual(NONE);
  });

  it('runs exactly after a release with DEPLOY_ENABLED "true"', () => {
    expect(mismatches(MATRIX, deployRuns, shouldDeploy)).toEqual(NONE);
    expect(MATRIX.some(shouldDeploy)).toBe(true);
  });

  it.each([
    ['unset', undefined],
    ["''", ''],
    ["'false'", 'false'],
  ])('PUBLISH_ENABLED alone (DEPLOY_ENABLED %s) publishes but never deploys', (_, deploy) => {
    const scenario = { ...BASE, deploy };
    expect(publishRuns(scenario)).toBe(true);
    expect(deployRuns(scenario)).toBe(false);
  });

  it('does not run when publish failed', () => {
    expect(runs(jobIf('deploy'), jobContext(BASE, FAILED))).toBe(false);
  });
});

describe('case-sensitive guard in publish and deploy', () => {
  // GitHub compares strings in expressions ignoring case (docs: Actions -> Expressions,
  // "GitHub ignores case when comparing strings"), so the if: of publish also lets a manual
  // start on a branch "Main" through. A shell step compares exactly and stops such runs.
  const JOBS = ['publish', 'deploy'];
  const CASE_VARIANTS = ['refs/heads/Main', 'refs/heads/MAIN'];

  const isGuard = (step: YamlMap): boolean => typeof step.run === 'string' && /\$\{?GITHUB_REF\b/.test(step.run);

  function guardOf(jobName: string): { step: YamlMap; index: number } {
    const all = steps(jobName);
    const index = all.findIndex(isGuard);
    if (index === -1) throw new Error(`jobs.${jobName} has no step that checks GITHUB_REF`);
    return { step: all[index], index };
  }

  /** Whether the guard of the job fails the step. GITHUB_* cannot be overridden by env. */
  function guardRejects(jobName: string, s: Scenario): boolean {
    const { step } = guardOf(jobName);
    const env = stepContext(s, jobName, step).env as Record<string, string>;
    const defaults = { GITHUB_REF: s.ref, GITHUB_ACTOR: s.actor, GITHUB_EVENT_NAME: s.event };
    for (const [name, value] of Object.entries(defaults)) {
      Object.defineProperty(env, name, { value, enumerable: true, configurable: true });
    }
    return guardExitCode(text(step.run, `jobs.${jobName} guard run`), env) !== 0;
  }

  /** Variables the condition of the guard reads, e.g. GITHUB_REF and GITHUB_ACTOR. */
  function guardVariables(jobName: string): string[] {
    const script = text(guardOf(jobName).step.run, `jobs.${jobName} guard run`);
    const head = script.split('\n').find((line) => line.trim().startsWith('if ')) ?? '';
    return [...head.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]);
  }

  /** Shell of a step: step shell, else defaults.run.shell of the job, else of the workflow. */
  function effectiveShell(jobName: string, step: YamlMap): string {
    const fromDefaults = (owner: YamlMap, where: string): string | undefined => {
      if (owner.defaults === undefined || owner.defaults === null) return undefined;
      const run = map(owner.defaults, `${where}.defaults`).run;
      if (run === undefined || run === null) return undefined;
      return optionalText(map(run, `${where}.defaults.run`).shell, `${where}.defaults.run.shell`);
    };
    return (
      optionalText(step.shell, 'step.shell') ??
      fromDefaults(job(jobName), `jobs.${jobName}`) ??
      fromDefaults(workflow, 'workflow') ??
      'bash'
    );
  }

  it.each(JOBS)('%s starts with the guard, which is neither skipped nor continued on error', (name) => {
    const { step, index } = guardOf(name);
    expect(index).toBe(0);
    expect(step.uses).toBeUndefined();
    expect(step['continue-on-error'] ?? 'false').toBe('false');
    expect(effectiveShell(name, step)).toMatch(/^bash\b/);
    for (const scenario of [BASE, ...CASE_VARIANTS.map((ref) => ({ ...BASE, event: 'workflow_dispatch', ref }))]) {
      const ctx = { ...stepContext(scenario, name, step), status: SUCCEEDED };
      expect(runs(optionalText(step.if, 'guard.if'), ctx)).toBe(true);
    }
  });

  it.each(JOBS)('%s: no env sets GITHUB_* for the guard or the variables its condition reads', (name) => {
    const step = guardOf(name).step;
    const keys = (value: YamlValue | undefined, where: string): string[] =>
      value === undefined || value === null ? [] : Object.keys(map(value, where));
    expect(keys(step.env, 'guard env').filter((key) => key.startsWith('GITHUB_'))).toEqual([]);
    const guardReads = guardVariables(name);
    expect(guardReads).toEqual(expect.arrayContaining(['GITHUB_REF', 'GITHUB_ACTOR']));
    const outer = [...keys(workflow.env, 'env'), ...keys(job(name).env, `jobs.${name}.env`)];
    expect(outer.filter((key) => guardReads.includes(key))).toEqual([]);
  });

  it.each(JOBS.flatMap((name) => CASE_VARIANTS.map((ref) => [name, ref])))(
    '%s: the guard stops a manual start on %s',
    (name, ref) => {
      expect(guardRejects(name, { ...BASE, event: 'workflow_dispatch', ref })).toBe(true);
      expect(guardRejects(name, { ...BASE, ref })).toBe(true);
    },
  );

  it.each(JOBS)('%s: the guard lets push and manual start on refs/heads/main by a person pass', (name) => {
    expect(guardRejects(name, BASE)).toBe(false);
    expect(guardRejects(name, { ...BASE, event: 'workflow_dispatch' })).toBe(false);
  });

  it.each(JOBS)('%s: the guard stops dependabot[bot] on refs/heads/main', (name) => {
    expect(guardRejects(name, { ...BASE, actor: 'dependabot[bot]' })).toBe(true);
    expect(guardRejects(name, { ...BASE, event: 'workflow_dispatch', actor: 'dependabot[bot]' })).toBe(true);
  });

  it.each(JOBS)('%s: the guard stops every other ref', (name) => {
    const refs = ['refs/heads/main-alt', 'refs/heads/main/', 'refs/heads/feature/neuer-artikel', 'refs/pull/7/merge'];
    for (const ref of [...refs, 'refs/tags/v1.0.0', 'main', '']) {
      expect(guardRejects(name, { ...BASE, ref }), ref).toBe(true);
    }
  });

  it('publish: the guard comes before the GHCR login and the push', () => {
    const all = steps('publish');
    const guard = guardOf('publish').index;
    const login = all.findIndex((s) => String(s.uses ?? '').startsWith('docker/login-action@'));
    const push = all.findIndex((s) => /\bdocker push\b/.test(String(s.run ?? '')));
    expect(login).toBeGreaterThan(guard);
    expect(push).toBeGreaterThan(guard);
  });

  it('deploy: the guard comes before the SSH step', () => {
    const all = steps('deploy');
    const ssh = all.findIndex((s) => /(^|\s)ssh\s/m.test(String(s.run ?? '')));
    expect(ssh).toBeGreaterThan(guardOf('deploy').index);
  });

  it('if: and guard together let publish and deploy through exactly as decided, also for case variants', () => {
    const variants: Scenario[] = [];
    for (const event of ['push', 'workflow_dispatch'])
      for (const ref of [...CASE_VARIANTS, 'refs/heads/main'])
        for (const actor of ['maintainer-example', 'dependabot[bot]'])
          for (const [publish, deploy] of [
            ['true', undefined],
            [undefined, 'true'],
            ['true', 'true'],
          ])
            variants.push({ event, ref, actor, publish, deploy });
    const all = [...MATRIX, ...variants];
    const publishes = (s: Scenario): boolean => publishRuns(s) && !guardRejects('publish', s);
    const deploys = (s: Scenario): boolean => {
      const publishResult = publishes(s) ? SUCCEEDED : publishRuns(s) ? FAILED : SKIPPED;
      return runs(jobIf('deploy'), jobContext(s, publishResult)) && !guardRejects('deploy', s);
    };
    expect(mismatches(all, publishes, shouldRelease)).toEqual(NONE);
    expect(mismatches(all, deploys, shouldDeploy)).toEqual(NONE);
    expect(variants.some(shouldDeploy)).toBe(true);
  });
});

describe('permissions and order of the jobs', () => {
  it('top-level permissions are exactly contents: read', () => {
    expect(workflow.permissions).toEqual({ contents: 'read' });
  });

  it('publish needs quality, e2e and scan and does not run when one of them failed', () => {
    expect(needs('publish')).toEqual(expect.arrayContaining(['quality', 'e2e', 'scan']));
    expect(publishRuns(BASE, SUCCEEDED)).toBe(true);
    expect(publishRuns(BASE, FAILED)).toBe(false);
    expect(publishRuns(BASE, SKIPPED)).toBe(false);
  });

  it('only the publish job may write packages', () => {
    const writers: string[] = [];
    for (const name of Object.keys(jobs)) {
      const permissions = job(name).permissions;
      if (permissions === undefined || permissions === null) continue;
      if (typeof permissions === 'string') {
        if (permissions === 'write-all') writers.push(`${name}: write-all`);
        continue;
      }
      if (map(permissions, `jobs.${name}.permissions`).packages === 'write') writers.push(name);
    }
    expect(writers).toEqual(['publish']);
  });
});

describe('SITE_URL guard', () => {
  const guard = (): YamlMap => steps('image')[0];
  const SITE_URLS = [undefined, '', 'https://www.meine-domain.de'];

  it('is the first step of the image job, before the build, and fails the job', () => {
    const step = guard();
    expect(step.uses).toBeUndefined();
    expect(text(step.run, 'guard.run')).toMatch(/\bexit\s+[1-9]\d*\b/);
    expect(step['continue-on-error'] ?? 'false').toBe('false');
    const build = steps('image').findIndex((s) => String(s.uses ?? '').startsWith('docker/build-push-action@'));
    expect(build).toBeGreaterThan(0);
  });

  it('fires exactly when a release would run without SITE_URL', () => {
    const scenarios = MATRIX.flatMap((s) => SITE_URLS.map((siteUrl) => ({ ...s, siteUrl })));
    const step = guard();
    const fires = (s: Scenario): boolean =>
      runs(optionalText(step.if, 'guard.if'), { ...stepContext(s, 'image', step), status: SUCCEEDED });
    expect(mismatches(scenarios, fires, (s) => shouldRelease(s) && !s.siteUrl)).toEqual(NONE);
    expect(scenarios.some(fires)).toBe(true);
  });
});

describe('CHECK_LIVE build argument', () => {
  const buildArg = (name: string): string => {
    const build = steps('image').find((s) => String(s.uses ?? '').startsWith('docker/build-push-action@'));
    const args = text(map(build?.with, 'build step with')['build-args'], 'build-args').split('\n');
    const lines = args.filter((line) => line.trim().startsWith(`${name}=`));
    expect(lines).toHaveLength(1);
    return lines[0].trim().slice(name.length + 1);
  };

  it('is "1" exactly for a release, otherwise "0"', () => {
    const value = buildArg('CHECK_LIVE');
    const got = (s: Scenario): string => interpolate(value, stepContext(s, 'image'));
    expect(mismatches(MATRIX, got, (s) => (shouldRelease(s) ? '1' : '0'))).toEqual(NONE);
  });

  it('a release builds with the configured SITE_URL', () => {
    const scenario = { ...BASE, siteUrl: 'https://www.meine-domain.de' };
    expect(interpolate(buildArg('SITE_URL'), stepContext(scenario, 'image'))).toBe('https://www.meine-domain.de');
  });

  it('is declared in the Dockerfile and handed to the build', () => {
    const dockerfile = read('site/Dockerfile');
    expect(dockerfile).toMatch(/^ARG CHECK_LIVE(=0)?\s*$/m);
    expect(dockerfile).toMatch(/^ENV\b.*\bCHECK_LIVE=\$\{?CHECK_LIVE\}?(\s|$)/m);
  });
});

describe('image reference on the server', () => {
  it('deploy/.env.example has WEBSITE_IMAGE as digest placeholder, never a tag like :latest', () => {
    const lines = read('deploy/.env.example')
      .split('\n')
      .filter((line) => /^\s*WEBSITE_IMAGE\s*=/.test(line));
    expect(lines).toHaveLength(1);
    const value = lines[0]
      .slice(lines[0].indexOf('=') + 1)
      .trim()
      .replace(/^(['"])(.*)\1$/, '$2');
    expect(value).toMatch(/^[^\s@]+@sha256:\S+$/);
    expect(value.split('@')[0].split('/').pop()).not.toContain(':');
    expect(value).not.toMatch(/:latest\b/i);
  });

  it('deploy/compose.yml takes the website image only from WEBSITE_IMAGE, without a fallback tag', () => {
    const compose = read('deploy/compose.yml');
    const website = map(map(map(parseYaml(compose), 'compose').services, 'services').website, 'website');
    expect(text(website.image, 'website.image')).toMatch(/^\$\{WEBSITE_IMAGE(:?\?[^}]*)?\}$/);
    expect(compose).not.toMatch(/:latest\b/i);
  });
});

describe('actions', () => {
  const PINNED = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/;

  it('every uses: in every workflow is pinned to a full 40-character commit SHA', () => {
    const dir = '.github/workflows';
    const files = readdirSync(join(ROOT, dir)).filter((f) => /\.ya?ml$/.test(f));
    expect(files).toContain('ci-cd.yml');
    const unpinned: string[] = [];
    let count = 0;
    for (const file of files) {
      const content = read(`${dir}/${file}`);
      const code = content
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n');
      const refs = [...code.matchAll(/^\s*(?:-\s+)?uses:\s*(.*)$/gm)].map((m) =>
        m[1]
          .replace(/\s+#.*$/, '')
          .trim()
          .replace(/^(['"])(.*)\1$/, '$2'),
      );
      // Every "uses:" must be found by the line pattern, nothing hides in other syntax.
      expect(refs.length).toBe((code.match(/\buses\s*:/g) ?? []).length);
      count += refs.length;
      unpinned.push(...refs.filter((ref) => !PINNED.test(ref)).map((ref) => `${file}: ${ref}`));
    }
    expect(unpinned).toEqual([]);
    expect(count).toBeGreaterThan(0);
  });

  it('the line scan sees every uses: of ci-cd.yml that the YAML reader sees', () => {
    let fromYaml = 0;
    for (const name of Object.keys(jobs)) {
      if (job(name).uses !== undefined) fromYaml++;
      if (job(name).steps === undefined) continue;
      for (const step of steps(name)) if (step.uses !== undefined) fromYaml++;
    }
    const fromLines = (read('.github/workflows/ci-cd.yml').match(/^\s*(?:-\s+)?uses:/gm) ?? []).length;
    expect(fromYaml).toBe(fromLines);
    expect(fromYaml).toBeGreaterThan(0);
  });
});
