#!/usr/bin/env python3
"""Reject application direct egress and DNS, allowing only local RPC binds.

This is a source-policy guard, not a Rust parser or an audit of Arti internals.
Test files and explicitly cfg(test)/test-support items are excluded. All other
workspace code has zero permitted TCP dials; only rpc::bind_local may bind.
"""
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
RPC = Path('crates/runtime/src/rpc.rs')
RAW_LITERAL = re.compile(r'(?:br|r)(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[^}]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'")


def blank(text):
    return ''.join('\n' if char == '\n' else ' ' for char in text)


def mask_literals(text):
    """Preserve positions while masking comments and Rust string/char literals."""
    result = list(text)
    cursor = 0
    while cursor < len(text):
        end = cursor
        if text.startswith('//', cursor):
            end = text.find('\n', cursor)
            if end < 0:
                end = len(text)
        elif text.startswith('/*', cursor):
            depth, end = 1, cursor + 2
            while end < len(text) and depth:
                if text.startswith('/*', end):
                    depth += 1
                    end += 2
                elif text.startswith('*/', end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = RAW_LITERAL.match(text, cursor)
            if raw:
                terminator = '"' + raw.group(1)
                at = text.find(terminator, raw.end())
                end = len(text) if at < 0 else at + len(terminator)
            elif text[cursor] == '"':
                end = cursor + 1
                while end < len(text):
                    if text[end] == '\\':
                        end += 2
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
            elif text[cursor] == "'":
                char = CHAR_LITERAL.match(text, cursor)
                if char:
                    end = char.end()
        if end > cursor:
            result[cursor:end] = blank(text[cursor:end])
            cursor = end
        else:
            cursor += 1
    return ''.join(result)


def item_end(code, start):
    """Find the end of a function/module/item, using already-masked Rust text."""
    opening = code.find('{', start)
    semicolon = code.find(';', start)
    if semicolon >= 0 and (opening < 0 or semicolon < opening):
        return semicolon + 1
    if opening < 0:
        return len(code)
    depth = 1
    for index in range(opening + 1, len(code)):
        depth += (code[index] == '{') - (code[index] == '}')
        if depth == 0:
            return index + 1
    return len(code)


def production(text):
    code = mask_literals(text)
    # Deliberately accept only these explicit test gates, not arbitrary cfgs.
    attr = r'#\[cfg\((?:test|any\(\s*test\s*,\s*feature\s*=\s*"test-support"\s*\))\)\]'
    for match in reversed(list(re.finditer(attr, text))):
        if code[match.start()] != '#':
            continue
        rest = code[match.end():]
        item = re.match(r'\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|mod|struct|enum|impl|use|type|const|static)\b', rest)
        if item:
            end = item_end(code, match.end() + item.end())
            code = code[:match.start()] + blank(code[match.start():end]) + code[end:]
    return code


def inspect(relative, text):
    code = production(text)
    failures = []
    local = re.search(r'\bfn\s+bind_local\s*\(', code) if relative == RPC else None
    local_end = item_end(code, local.end()) if local else 0
    for pattern, reason in (
        (r'\bTcpStream\s*::\s*connect(?:_timeout)?\s*\(', 'direct TCP dial'),
        (r'\b(lookup_host|lookup_addr|ToSocketAddrs|UdpSocket|TcpSocket|getaddrinfo)\b', 'resolver/socket API'),
        (r'\b(socket2|snow|tokio_socks)\s*::', 'retired transport API'),
    ):
        for match in re.finditer(pattern, code):
            failures.append(f'{relative}:{code.count(chr(10), 0, match.start()) + 1}: forbidden {reason}')
    binds = list(re.finditer(r'\bTcpListener\s*::\s*bind\s*\(', code))
    for match in binds:
        if not local or not local.start() < match.start() < local_end:
            failures.append(f'{relative}:{code.count(chr(10), 0, match.start()) + 1}: bind outside rpc::bind_local')
    if local:
        body = code[local.start():local_end]
        if not re.search(r'if\s+addr\.ip\(\)\s*!=\s*(?:std::net::)?IpAddr::V4\(Ipv4Addr::LOCALHOST\)', body):
            failures.append(f'{relative}: local RPC binder must enforce IPv4 localhost')
        if len(binds) != 1:
            failures.append(f'{relative}: expected one explicitly allowlisted local RPC bind')
    return failures


def dependencies(manifest):
    for kind, value in manifest.items():
        if kind in ('dependencies', 'dev-dependencies', 'build-dependencies', 'patch'):
            yield value
        if isinstance(value, dict):
            yield from dependencies(value)


def main():
    errors = []
    # Regression checks: multiline calls cannot evade the guard; tests/comments
    # do not trigger production findings; a non-test cfg stays covered.
    assert inspect(Path('src/x.rs'), 'TcpStream\n::connect("x");')
    assert not inspect(Path('src/x.rs'), '#[cfg(test)] mod tests { TcpStream::connect("x"); }')
    assert inspect(Path('src/x.rs'), '#[cfg(not(test))] fn x() { TcpStream::connect("x"); }')
    assert not inspect(Path('src/x.rs'), '// TcpStream::connect("x");\nlet s = "UdpSocket";')
    for path in sorted((ROOT / 'crates').rglob('*.rs')):
        relative = path.relative_to(ROOT)
        if any(part in ('tests', 'benches') for part in relative.parts):
            continue
        errors.extend(inspect(relative, path.read_text()))
    for path in [ROOT / 'Cargo.toml', *(ROOT / 'crates').glob('*/Cargo.toml')]:
        for table in dependencies(tomllib.loads(path.read_text())):
            for name, spec in table.items():
                package = spec.get('package', name) if isinstance(spec, dict) else name
                if package in ('snow', 'socket2', 'tokio-socks', 'libtor', 'torut'):
                    errors.append(f'{path.relative_to(ROOT)}: forbidden direct dependency {package}')
    if (ROOT / 'crates/p2p/src/noise.rs').exists():
        errors.append('retired Noise implementation still exists')
    explorer = (ROOT / 'crates/runtime/src/explorer.html').read_text()
    if 'content="connect-src \'self\'"' not in explorer or "mode:'same-origin'" not in explorer:
        errors.append('explorer RPC must retain same-origin fetch and CSP restrictions')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Tor-only guard passed: zero production TCP dials; binds allowed only in rpc::bind_local; no local DNS.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
