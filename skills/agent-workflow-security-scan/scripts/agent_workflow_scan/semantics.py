"""Bounded, non-executing semantic summaries for Dify node instances.

Descriptions and parameter schemas declare possible capabilities, not effects.
This is deliberately not a full Python/JavaScript interpreter or proof of safety.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from functools import lru_cache
import re
from typing import Any


DSL_TEMPLATE = re.compile(r"\{\{#([^#]+)#\}\}")
TEMPLATE = re.compile(r"\{\{\s*[\w.]+\s*\}\}|\{%.*?%\}", re.S)


@dataclass
class CodeSummary:
    parsed: bool = True
    templated_source: bool = False
    capabilities: set[str] = field(default_factory=set)
    inputs: dict[str, set[str]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    unknown_calls: bool = False
    return_inputs: set[str] = field(default_factory=set)


def _call_kind(name: str) -> str | None:
    if name in {"eval", "exec", "builtins.eval", "builtins.exec", "os.system", "os.popen",
                "pickle.loads", "pickle.load", "dill.loads", "marshal.loads"}:
        return "CODE_EXECUTION"
    if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"} or name.startswith("os.exec") or name.startswith("os.spawn"):
        return "CODE_EXECUTION"
    if name.endswith((".execute", ".executemany", ".executescript", ".raw")):
        return "DATABASE_EXECUTION"
    if name.startswith(("requests.", "httpx.", "urllib.request.", "socket.")):
        if name.endswith((".post", ".put", ".patch", ".delete", ".send", ".sendall")):
            return "NETWORK_WRITE"
        return "NETWORK_READ"
    if name in {"os.remove", "os.unlink", "shutil.rmtree"}:
        return "RESOURCE_DELETE"
    return None


def _sink_values(call: ast.Call, name: str, kind: str) -> list[ast.AST]:
    values = list(call.args[:1]) + [k.value for k in call.keywords if k.arg in {"sql", "query", "command", "args", "url", "source"}]
    if name.endswith('.request') and len(call.args) > 1:
        values = [call.args[1], *[k.value for k in call.keywords if k.arg == 'url']]
    if name.startswith('subprocess.') and values and isinstance(values[0], (ast.List, ast.Tuple)):
        shell = next((k.value for k in call.keywords if k.arg == 'shell'), ast.Constant(False))
        vector = values[0].elts
        if isinstance(shell, ast.Constant) and shell.value is False and vector:
            # A fixed executable with data argv isn't shell source. Interpreter
            # command switches and dynamic executable names remain source sinks.
            if not isinstance(vector[0], ast.Constant):
                return [vector[0]]
            executable = str(vector[0].value).replace('\\', '/').split('/')[-1].lower()
            if executable in {'python', 'python3', 'python.exe', 'bash', 'sh', 'node', 'powershell', 'pwsh', 'cmd', 'cmd.exe'}:
                for i, arg in enumerate(vector[1:], 1):
                    if isinstance(arg, ast.Constant) and str(arg.value).lower() in {'-c', '-e', '/c', '-command', '-encodedcommand'}:
                        return vector[i + 1:]
                return vector[1:]  # Dynamic script filenames still execute.
            return []
    return values


@lru_cache(maxsize=256)
def analyze_code(code: str, language: str = "python3") -> CodeSummary:
    """Trace parameters through assignments/helpers to actual call arguments.

    Union joins deliberately retain both branches; unknown reflection is exposed
    as coverage, never treated as a sanitizer. Strings/comments aren't calls.
    """
    out = CodeSummary(templated_source=bool(DSL_TEMPLATE.search(code)))
    if out.templated_source:
        out.capabilities.add('CODE_EXECUTION')
    if language not in {"python", "python3", ""}:
        out.parsed = False
        return out
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        out.parsed = False
        out.templated_source |= bool(TEMPLATE.search(code))
        if out.templated_source:
            out.capabilities.add('CODE_EXECUTION')
        return out
    if sum(1 for _ in ast.walk(tree)) > 30000:
        out.parsed = False
        return out
    aliases: dict[str, str] = {}
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                imported_roots.add(item.name.split('.')[0])
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            imported_roots.add(str(node.module).split('.')[0])
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def resolve(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{resolve(node.value)}.{node.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == '__import__' and node.args and isinstance(node.args[0], ast.Constant):
                return str(node.args[0].value)
            if node.func.id == 'getattr' and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                return f"{resolve(node.args[0])}.{node.args[1].value}"
        return ""

    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    summaries: dict[str, dict[str, set[str]]] = {}
    # Fixed-point helper summaries, bounded even for recursive user code.
    for _ in range(min(len(functions) + 1, 16)):
        changed = False
        for name, fn in functions.items():
            params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]]
            taint = {p: {p} for p in params}
            def deps(value: ast.AST) -> set[str]:
                return set().union(*(taint.get(n.id, set()) for n in ast.walk(value) if isinstance(n, ast.Name)))
            body = list(ast.walk(fn))
            # Assignment joins are conservative, including forward loop flow.
            for _pass in range(min(len(body), 12)):
                grew = False
                for n in body:
                    if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign, ast.For, ast.comprehension)):
                        value = n.iter if isinstance(n, (ast.For, ast.comprehension)) else n.value
                        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                        for target in targets:
                            if isinstance(target, (ast.Subscript, ast.Attribute)):
                                target = target.value
                            if isinstance(target, ast.Name) and value is not None:
                                values = deps(value)
                                old = taint.setdefault(target.id, set())
                                grew |= not values <= old
                                old.update(values)
                                resolved = resolve(value)
                                if resolved:
                                    aliases[target.id] = resolved
                if not grew:
                    break
            effects: dict[str, set[str]] = {}
            if name == 'main':
                out.return_inputs = set().union(*(deps(n.value) for n in body if isinstance(n, ast.Return) and n.value is not None))
            for n in body:
                if not isinstance(n, ast.Call):
                    continue
                called = resolve(n.func)
                if called and called not in out.calls:
                    out.calls.append(called)
                kind = _call_kind(called)
                if kind:
                    # SQL bind values (arg 1) aren't SQL source; subprocess shell
                    # strings and interpreter source are argument 0.
                    values = _sink_values(n, called, kind)
                    effects.setdefault(kind, set()).update(set().union(*(deps(v) for v in values)))
                if called in summaries:
                    callee = functions[called]
                    args = [a.arg for a in [*callee.args.posonlyargs, *callee.args.args]]
                    bound = dict(zip(args, n.args))
                    bound.update({k.arg: k.value for k in n.keywords if k.arg})
                    for effect, used in summaries[called].items():
                        effects.setdefault(effect, set()).update(set().union(*(deps(bound[p]) for p in used if p in bound)))
                supported_data_modules = {'json', 're', 'html', 'urllib', 'math', 'datetime', 'time', 'typing', 'collections', 'itertools', 'functools', 'operator', 'uuid', 'base64', 'hashlib', 'string', 'decimal', 'statistics', 'copy', 'ast'}
                unknown_import = called.split('.')[0] in imported_roots - supported_data_modules and not kind and called not in summaries
                dynamic_callable = isinstance(n.func, ast.Name) and n.func.id in params
                data_chain_methods = {'.strip', '.lstrip', '.rstrip', '.lower', '.upper', '.casefold', '.replace', '.split', '.join', '.encode', '.decode', '.get', '.items', '.keys', '.values'}
                unresolved_chain = called.startswith('.') and called not in data_chain_methods
                if not called or unresolved_chain or called in {"getattr", "globals", "locals"} or unknown_import or dynamic_callable:
                    out.unknown_calls = True
            if summaries.get(name) != effects:
                changed = True
                summaries[name] = effects
        if not changed:
            break
    # main is the Dify entry point; preserve module-level effect evidence too.
    active = summaries.get('main', {}) if 'main' in functions else {
        kind: set().union(*(effects.get(kind, set()) for effects in summaries.values()))
        for kind in {k for effects in summaries.values() for k in effects}
    }
    out.inputs = active
    out.capabilities = set(active)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                kind = _call_kind(resolve(node.func))
                if kind:
                    out.capabilities.add(kind)
    if out.templated_source:
        out.capabilities.add("CODE_EXECUTION")
    return out


def field_matches(field: str, words: Any) -> bool:
    """Exact semantic components, never `code` within `codeListInput`."""
    text = field.lower()
    parts = set(re.split(r"[^a-z0-9]+", text))
    aliases = {"targeturl": "url", "callbackurl": "url", "baseurl": "url",
               "rawsql": "sql", "sqlquery": "sql", "commandtext": "command",
               "filepath": "path", "filename": "filename"}
    parts.add(aliases.get(text, text))
    return bool(parts & {w.lower() for w in words}) or any(
        re.search(r'(?<![a-z0-9])' + re.escape(w.lower()) + r'(?![a-z0-9])', text)
        for w in words
    )


def effective_value(config: dict[str, Any], key: str) -> Any:
    for section in ("tool_configurations", "tool_parameters", "agent_parameters"):
        values = config.get(section)
        if isinstance(values, dict) and key in values:
            item = values[key]
            if isinstance(item, dict):
                return item.get('value') if item.get('type') == 'constant' else None
            return item
    return config.get(key)


def memory_mode(config: dict[str, Any], capabilities: list[str]) -> str:
    """none/session/persistent/unknown from effective instance, not schemas."""
    marker = config.get('_scanner_registry') or {}
    if isinstance(marker, dict) and all(marker.get(k) for k in ('matched', 'trusted_source', 'definition_version', 'integrity_control')):
        if marker.get('memory_mode') in {'none', 'session', 'persistent', 'unknown'}:
            return marker['memory_mode']
    if 'MEMORY_WRITE' in capabilities or 'PERSISTENT_MEMORY' in capabilities:
        return 'persistent'
    keep = effective_value(config, 'keep_conversation')
    if keep is False:
        return 'none'
    if keep is True:
        return 'session'
    identity = ' '.join(str(config.get(k, '')) for k in ('tool_name', 'operation', 'name', 'title')).lower()
    if re.search(r'(?:write|store|save|persist|remember)[_ -]*(?:memory)?|记忆写入|持久记忆', identity) and 'memory' in identity:
        return 'persistent'
    if any(key in (config.get(section) or {}) for section in ('tool_configurations', 'tool_parameters')
           for key in ('keep_conversation',)):
        return 'unknown'
    return 'none'


def url_target_kind(config: dict[str, Any]) -> str:
    """Distinguish address interpolation from fixed authority path/query data."""
    url = config.get('url') or config.get('endpoint') or config.get('base_url') or ''
    if isinstance(url, dict):
        url = url.get('value', '')
    if not isinstance(url, str):
        return 'unknown'
    # Shield template punctuation before parsing authority; '?' inside a query
    # value cannot become the authority of an absolute URL.
    masked = re.sub(r'\{\{.*?\}\}', 'DYNAMIC', url)
    absolute = re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)', masked)
    if absolute and 'DYNAMIC' not in absolute.group(1):
        return 'fixed_authority'
    if 'DYNAMIC' in masked:
        return 'dynamic_authority'
    return 'unknown'
