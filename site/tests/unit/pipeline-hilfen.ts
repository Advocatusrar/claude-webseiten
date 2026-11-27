// Test helpers for tests/unit/pipeline.test.ts: a small YAML reader for the subset used in
// .github/workflows/ci-cd.yml and an evaluator for the subset of GitHub Actions expressions
// used in its conditions. Both fail loudly on anything outside that subset, so a change to
// the workflow can never be skipped silently; extend the helpers instead.
//
// Expression semantics follow the GitHub documentation (Actions -> Expressions):
// - strings are compared ignoring case, values of different types are compared as numbers;
// - && and || return one of their operands, falsy are false, 0, -0, NaN, '' and null;
// - an unset configuration variable (vars.X) is the empty string.

export type YamlValue = string | null | YamlValue[] | { [key: string]: YamlValue };

interface Line {
  no: number;
  indent: number;
  text: string;
  raw: string;
}

const KEY = /^([A-Za-z0-9_.-]+|'[^']*'|"[^"]*"):(?:\s+(.*))?$/;

function isBlank(line: Line): boolean {
  return line.text === '' || line.text.startsWith('#');
}

function isSequenceItem(text: string): boolean {
  return text === '-' || text.startsWith('- ');
}

/** Removes a trailing " # comment" outside of quotes. */
export function stripComment(value: string): string {
  let quote = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(value[i - 1]))) {
      return value.slice(0, i).trimEnd();
    }
  }
  return value.trimEnd();
}

function scalar(value: string, line: Line): string {
  if (value.startsWith("'")) {
    if (!value.endsWith("'") || value.length < 2) throw yamlError(line, 'unterminated single-quoted string');
    return value.slice(1, -1).replace(/''/g, "'");
  }
  if (value.startsWith('"')) return JSON.parse(value) as string;
  if (/^[{&*!%@`|>]/.test(value)) throw yamlError(line, `unsupported YAML syntax: ${value}`);
  return value;
}

function key(raw: string, line: Line): string {
  return raw.startsWith("'") || raw.startsWith('"') ? scalar(raw, line) : raw;
}

function yamlError(line: Line, message: string): Error {
  return new Error(`YAML line ${line.no}: ${message} (${line.raw.trim()})`);
}

class YamlReader {
  constructor(private readonly lines: Line[]) {}

  next(from: number): number {
    for (let i = from; i < this.lines.length; i++) if (!isBlank(this.lines[i])) return i;
    return -1;
  }

  node(at: number, minIndent: number): [YamlValue, number] {
    const line = this.lines[at];
    if (line.indent < minIndent) throw yamlError(line, 'indentation too small');
    return isSequenceItem(line.text) ? this.sequence(at, line.indent) : this.mapping(at, line.indent);
  }

  mapping(at: number, indent: number): [YamlValue, number] {
    const result: { [key: string]: YamlValue } = {};
    let pos = at;
    for (;;) {
      const k = this.next(pos);
      if (k === -1 || this.lines[k].indent < indent) break;
      const line = this.lines[k];
      if (line.indent > indent) throw yamlError(line, 'unexpected indentation');
      if (isSequenceItem(line.text)) break;
      const match = KEY.exec(line.text);
      if (!match) throw yamlError(line, 'expected "key: value"');
      const name = key(match[1], line);
      if (name in result) throw yamlError(line, `duplicate key ${name}`);
      const rest = stripComment(match[2] ?? '');
      if (rest === '') {
        const child = this.next(k + 1);
        if (child !== -1 && this.lines[child].indent > indent) {
          [result[name], pos] = this.node(child, indent + 1);
        } else if (child !== -1 && this.lines[child].indent === indent && isSequenceItem(this.lines[child].text)) {
          [result[name], pos] = this.sequence(child, indent);
        } else {
          result[name] = null;
          pos = k + 1;
        }
      } else if (rest === '|' || rest === '|-') {
        [result[name], pos] = this.blockScalar(k, indent, rest === '|');
      } else if (rest.startsWith('[')) {
        result[name] = this.flowSequence(rest, line);
        pos = k + 1;
      } else {
        result[name] = scalar(rest, line);
        pos = k + 1;
      }
    }
    return [result, pos];
  }

  sequence(at: number, indent: number): [YamlValue, number] {
    const result: YamlValue[] = [];
    let pos = at;
    for (;;) {
      const k = this.next(pos);
      if (k === -1 || this.lines[k].indent < indent) break;
      const line = this.lines[k];
      if (line.indent > indent) throw yamlError(line, 'unexpected indentation');
      if (!isSequenceItem(line.text)) break;
      const afterDash = line.text.slice(1);
      const item = afterDash.trimStart();
      const itemIndent = indent + 1 + (afterDash.length - item.length);
      const content = stripComment(item);
      if (content === '') {
        const child = this.next(k + 1);
        if (child !== -1 && this.lines[child].indent > indent) {
          let value: YamlValue;
          [value, pos] = this.node(child, indent + 1);
          result.push(value);
        } else {
          result.push(null);
          pos = k + 1;
        }
      } else if (KEY.test(item)) {
        // "- key: value" starts a mapping whose keys are aligned with "key".
        this.lines[k] = { no: line.no, indent: itemIndent, text: item, raw: line.raw };
        let value: YamlValue;
        [value, pos] = this.mapping(k, itemIndent);
        result.push(value);
      } else if (isSequenceItem(item)) {
        throw yamlError(line, 'nested inline sequences are not supported');
      } else {
        result.push(content.startsWith('[') ? this.flowSequence(content, line) : scalar(content, line));
        pos = k + 1;
      }
    }
    return [result, pos];
  }

  blockScalar(at: number, indent: number, keepNewline: boolean): [string, number] {
    const content: string[] = [];
    let pos = at + 1;
    while (pos < this.lines.length) {
      const line = this.lines[pos];
      if (line.raw.trim() !== '' && line.indent <= indent) break;
      content.push(line.raw);
      pos++;
    }
    while (content.length > 0 && content[content.length - 1].trim() === '') content.pop();
    const first = content.find((l) => l.trim() !== '');
    const cut = first === undefined ? 0 : first.length - first.trimStart().length;
    const text = content.map((l) => l.slice(cut)).join('\n');
    return [keepNewline && text !== '' ? `${text}\n` : text, pos];
  }

  flowSequence(value: string, line: Line): YamlValue[] {
    if (!value.endsWith(']')) throw yamlError(line, 'unterminated flow sequence');
    const inner = value.slice(1, -1).trim();
    if (inner === '') return [];
    if (/[[\]{}]/.test(inner)) throw yamlError(line, 'nested flow collections are not supported');
    return inner.split(',').map((part) => scalar(part.trim(), line));
  }
}

/** Reads the YAML subset of the workflow. All scalars stay strings (no type conversion). */
export function parseYaml(source: string): YamlValue {
  const lines: Line[] = source.split(/\r?\n/).map((raw, i) => {
    const text = raw.trimStart();
    if (/\t/.test(raw.slice(0, raw.length - text.length))) {
      throw new Error(`YAML line ${i + 1}: tab in indentation`);
    }
    return { no: i + 1, indent: raw.length - text.length, text: text.trimEnd(), raw };
  });
  const reader = new YamlReader(lines);
  const first = reader.next(0);
  if (first === -1) return null;
  const [value, end] = reader.node(first, 0);
  const rest = reader.next(end);
  if (rest !== -1) throw yamlError(lines[rest], 'unexpected content');
  return value;
}

// ---------------------------------------------------------------------------------------
// Expressions

export type ExprValue = string | number | boolean | null;

export interface ExprContext {
  github: Record<string, string>;
  vars: Record<string, string>;
  /** Without env, a reference to env.* is an error (as in jobs.<id>.if). */
  env?: Record<string, string>;
  /** Result of the jobs in needs (or the previous steps), for success(), failure(), cancelled(). */
  status?: { success: boolean; failure: boolean; cancelled: boolean };
}

type Node =
  | { kind: 'literal'; value: ExprValue }
  | { kind: 'ref'; context: string; name: string }
  | { kind: 'not'; arg: Node }
  | { kind: 'binary'; op: '==' | '!=' | '&&' | '||'; left: Node; right: Node }
  | { kind: 'call'; name: string; args: Node[] };

type Token = { type: 'string' | 'number' | 'ident' | 'op'; value: string };

const TOKEN =
  /\s*(?:('(?:[^']|'')*')|(\d+(?:\.\d+)?)|([A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*)|(&&|\|\||==|!=|!|\(|\)|,))/y;

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  TOKEN.lastIndex = 0;
  while (TOKEN.lastIndex < source.length) {
    if (/^\s*$/.test(source.slice(TOKEN.lastIndex))) break;
    const start = TOKEN.lastIndex;
    const m = TOKEN.exec(source);
    if (!m) throw new Error(`unsupported expression syntax at "${source.slice(start)}" in: ${source}`);
    if (m[1] !== undefined) tokens.push({ type: 'string', value: m[1].slice(1, -1).replace(/''/g, "'") });
    else if (m[2] !== undefined) tokens.push({ type: 'number', value: m[2] });
    else if (m[3] !== undefined) tokens.push({ type: 'ident', value: m[3] });
    else tokens.push({ type: 'op', value: m[4] });
  }
  return tokens;
}

class ExprParser {
  private pos = 0;
  constructor(
    private readonly tokens: Token[],
    private readonly source: string,
  ) {}

  parse(): Node {
    const node = this.or();
    if (this.pos !== this.tokens.length) this.fail('unexpected token');
    return node;
  }

  private fail(message: string): never {
    const token = this.tokens[this.pos];
    throw new Error(`${message} ${token ? `"${token.value}"` : 'at end'} in expression: ${this.source}`);
  }

  private take(op: string): boolean {
    const token = this.tokens[this.pos];
    if (token?.type === 'op' && token.value === op) {
      this.pos++;
      return true;
    }
    return false;
  }

  private or(): Node {
    let left = this.and();
    while (this.take('||')) left = { kind: 'binary', op: '||', left, right: this.and() };
    return left;
  }

  private and(): Node {
    let left = this.equality();
    while (this.take('&&')) left = { kind: 'binary', op: '&&', left, right: this.equality() };
    return left;
  }

  private equality(): Node {
    let left = this.unary();
    for (;;) {
      if (this.take('==')) left = { kind: 'binary', op: '==', left, right: this.unary() };
      else if (this.take('!=')) left = { kind: 'binary', op: '!=', left, right: this.unary() };
      else return left;
    }
  }

  private unary(): Node {
    if (this.take('!')) return { kind: 'not', arg: this.unary() };
    return this.primary();
  }

  private primary(): Node {
    if (this.take('(')) {
      const inner = this.or();
      if (!this.take(')')) this.fail('expected ")" but found');
      return inner;
    }
    const token = this.tokens[this.pos];
    if (!token) this.fail('expected a value');
    this.pos++;
    if (token.type === 'string') return { kind: 'literal', value: token.value };
    if (token.type === 'number') return { kind: 'literal', value: Number(token.value) };
    if (token.type !== 'ident') {
      this.pos--;
      this.fail('expected a value but found');
    }
    if (token.value === 'true' || token.value === 'false') return { kind: 'literal', value: token.value === 'true' };
    if (token.value === 'null') return { kind: 'literal', value: null };
    if (this.take('(')) {
      const args: Node[] = [];
      if (!this.take(')')) {
        do args.push(this.or());
        while (this.take(','));
        if (!this.take(')')) this.fail('expected ")" but found');
      }
      return { kind: 'call', name: token.value, args };
    }
    const parts = token.value.split('.');
    if (parts.length !== 2) {
      this.pos--;
      this.fail('only context.property references are supported, found');
    }
    return { kind: 'ref', context: parts[0], name: parts[1] };
  }
}

const cache = new Map<string, Node>();

function parseExpression(source: string): Node {
  let node = cache.get(source);
  if (!node) {
    node = new ExprParser(tokenize(source), source).parse();
    cache.set(source, node);
  }
  return node;
}

/** Removes the ${{ }} around a condition, if the whole condition is wrapped. */
export function unwrap(condition: string): string {
  const m = /^\s*\$\{\{([\s\S]*)\}\}\s*$/.exec(condition);
  return m && !m[1].includes('}}') ? m[1].trim() : condition.trim();
}

function toNumber(value: ExprValue): number {
  if (value === null) return 0;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (typeof value === 'number') return value;
  return Number(value);
}

export function truthy(value: ExprValue): boolean {
  if (typeof value === 'number') return value !== 0 && !Number.isNaN(value);
  return value !== false && value !== '' && value !== null;
}

function equal(a: ExprValue, b: ExprValue): boolean {
  if (typeof a === 'string' && typeof b === 'string') return a.toUpperCase() === b.toUpperCase();
  if (typeof a === typeof b) return a === b;
  return toNumber(a) === toNumber(b);
}

export function toText(value: ExprValue): string {
  if (value === null) return '';
  return String(value);
}

function evaluateNode(node: Node, ctx: ExprContext): ExprValue {
  switch (node.kind) {
    case 'literal':
      return node.value;
    case 'not':
      return !truthy(evaluateNode(node.arg, ctx));
    case 'binary': {
      const left = evaluateNode(node.left, ctx);
      if (node.op === '&&') return truthy(left) ? evaluateNode(node.right, ctx) : left;
      if (node.op === '||') return truthy(left) ? left : evaluateNode(node.right, ctx);
      const same = equal(left, evaluateNode(node.right, ctx));
      return node.op === '==' ? same : !same;
    }
    case 'ref': {
      if (node.context === 'vars') return ctx.vars[node.name] ?? '';
      if (node.context === 'github') {
        const value = ctx.github[node.name];
        if (value === undefined) throw new Error(`github.${node.name} is not modelled in the test scenarios`);
        return value;
      }
      if (node.context === 'env') {
        if (!ctx.env) throw new Error(`env.${node.name} is not available here (env context missing)`);
        const value = ctx.env[node.name];
        if (value === undefined) throw new Error(`env.${node.name} is not defined`);
        return value;
      }
      throw new Error(`context ${node.context} is not modelled in the test scenarios`);
    }
    case 'call': {
      if (node.args.length === 0 && node.name === 'always') return true;
      if (node.args.length === 0 && (node.name === 'success' || node.name === 'failure' || node.name === 'cancelled')) {
        if (!ctx.status) throw new Error(`${node.name}() needs a job status, none given`);
        return ctx.status[node.name];
      }
      throw new Error(`function ${node.name}() is not modelled in the test scenarios`);
    }
  }
}

/** Evaluates one expression (with or without ${{ }}). */
export function evaluate(expression: string, ctx: ExprContext): ExprValue {
  return evaluateNode(parseExpression(unwrap(expression)), ctx);
}

/** Evaluates an if: condition to true or false. */
export function condition(expression: string, ctx: ExprContext): boolean {
  return truthy(evaluate(expression, ctx));
}

/** Replaces every ${{ }} in a value by its result as text, as GitHub does for env and with. */
export function interpolate(value: string, ctx: ExprContext): string {
  return value.replace(/\$\{\{([\s\S]*?)\}\}/g, (_, expression: string) => toText(evaluate(expression, ctx)));
}

/** Names of all functions called in an expression, e.g. always or failure. */
export function calledFunctions(expression: string): string[] {
  const names: string[] = [];
  const walk = (node: Node): void => {
    if (node.kind === 'call') {
      names.push(node.name);
      node.args.forEach(walk);
    } else if (node.kind === 'not') walk(node.arg);
    else if (node.kind === 'binary') {
      walk(node.left);
      walk(node.right);
    }
  };
  walk(parseExpression(unwrap(expression)));
  return names;
}

const STATUS_FUNCTIONS = ['success', 'failure', 'cancelled', 'always'];

/**
 * Whether a job or step with this if: runs. Like GitHub, a condition without a status
 * function gets an implicit success() && in front; a missing condition is success().
 */
export function runs(expression: string | undefined, ctx: ExprContext): boolean {
  const effective = expression ?? 'success()';
  if (!calledFunctions(effective).some((name) => STATUS_FUNCTIONS.includes(name))) {
    if (!ctx.status) throw new Error('runs() needs a job status');
    if (!ctx.status.success) return false;
  }
  return condition(effective, ctx);
}
