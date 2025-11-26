#!/usr/bin/env python3
from __future__ import annotations
import sys, re, os, ipaddress, argparse, unicodedata
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Tuple, Set, Dict


def read_lines(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            yield ln

def write_text_lines(path: str, items: Iterable[str]) -> None:
    dst = path
    with open(dst, "w", encoding="utf-8") as f:
        for x in items:
            f.write(f"{x}\n")

def clean_stream(lines: Iterable[str]) -> Iterator[str]:
    for raw in lines:
        t = raw.rstrip("\r\n")
        i = t.find("#")
        if i != -1:
            t = t[:i]
        t = t.strip()
        if t:
            yield t

def is_hosts_prefix_token(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False

def label_count(d: str) -> int:
    return d.count(".") + 1 if d else 0

def _idn_to_ascii(t: str) -> str:
    try:
        return t.encode("idna").decode("ascii")
    except Exception:
        return t

_INVISIBLE_RE = re.compile(r"[\u200B\u200C\u200D\u2060\ufeff]", re.UNICODE)
_WS_RE = re.compile(r"\s+", re.UNICODE)
_LDH_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RANGE_RE = re.compile(r"^\s*([^-\s]+)\s*-\s*([^\s]+)\s*$")

def _strip_invisible_and_spaces(t: str) -> str:
    t = _INVISIBLE_RE.sub("", t)
    return _WS_RE.sub("", t)

def _is_valid_hostname_ascii(puny: str) -> bool:
    if not puny or len(puny) > 253:
        return False
    parts = puny.split(".")
    for lbl in parts:
        if not (1 <= len(lbl) <= 63):
            return False
        if _LDH_LABEL_RE.fullmatch(lbl) is None:
            return False
    return True

def normalize_domain_base(s: str) -> str:
    t = unicodedata.normalize("NFC", s.strip())
    t = _strip_invisible_and_spaces(t).lower()
    t = re.sub(r"^[.]+", "", t).strip(".")
    if not t:
        return t
    puny = _idn_to_ascii(t)
    if not _is_valid_hostname_ascii(puny):
        return ""
    return puny

def strip_clean_prefixes(s: str) -> str:
    t = s.strip()
    while True:
        if t.startswith("*."):
            t = t[2:]; continue
        if t.startswith("."):
            t = t[1:]; continue
        break
    return t

def _normalize_mihomo_pattern_base(s: str) -> str:
    parts = s.strip().split(".")
    if not parts:
        return ""
    out: List[str] = []
    for lbl in parts:
        if lbl == "":
            return ""
        if lbl == "*":
            out.append("*"); continue
        t = unicodedata.normalize("NFC", lbl)
        t = _strip_invisible_and_spaces(t).lower()
        try:
            puny = t.encode("idna").decode("ascii")
        except Exception:
            return ""
        if _LDH_LABEL_RE.fullmatch(puny) is None:
            return ""
        out.append(puny)
    return ".".join(out).strip(".")

def split_leading_marker_mihomo(s: str) -> Tuple[str, str]:
    if s.startswith("+."):
        return ("suffix", _normalize_mihomo_pattern_base(s[2:]))
    if s.startswith("*.") or s.startswith(".*"):
        return ("suffix", _normalize_mihomo_pattern_base(s[2:]))
    if s.startswith("."):
        return ("suffix", _normalize_mihomo_pattern_base(s[1:]))
    return ("exact", _normalize_mihomo_pattern_base(s))

def _remove_wild_labels(base: str) -> str:
    parts = [p for p in base.split(".") if p and p != "*"]
    return ".".join(parts)

@dataclass
class _TrieNode:
    children: Dict[str, "_TrieNode"] = field(default_factory=dict)
    suffix: bool = False
    full: bool = False

def _labels_rev(base: str) -> List[str]:
    return base.split(".")[::-1] if base else []

def _trie_insert(root: _TrieNode, base: str, flag: str) -> None:
    node = root
    for lab in _labels_rev(base):
        node = node.children.setdefault(lab, _TrieNode())
    if flag == "suffix":
        node.suffix = True
    elif flag == "full":
        node.full = True

def _prune(node: _TrieNode, has_suffix_above: bool = False) -> None:
    if has_suffix_above:
        node.suffix = False
        node.full = False
        for ch in node.children.values():
            _prune(ch, True)
        return
    if node.suffix and node.full:
        node.full = False
    next_has_suffix = has_suffix_above or node.suffix
    for ch in node.children.values():
        _prune(ch, next_has_suffix)

def _trie_collect(node: _TrieNode, path_rev: List[str], out_suffix: Set[str], out_full: Set[str]) -> None:
    base = ".".join(path_rev[::-1]) if path_rev else ""
    if node.suffix and base:
        out_suffix.add(base)
    if node.full and base:
        out_full.add(base)
    for lab, ch in node.children.items():
        _trie_collect(ch, path_rev + [lab], out_suffix, out_full)

def optimize_suffix_full(entries: Iterable[Tuple[str, str]]) -> Tuple[Set[str], Set[str]]:
    root = _TrieNode()
    for t, b in entries:
        if b:
            _trie_insert(root, b, t)
    _prune(root, False)
    E: Set[str] = set()
    S: Set[str] = set()
    _trie_collect(root, [], S, E)
    return S, E

def dedup_other_rules(other_rules: Iterable[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    kw: List[str] = []; rx: List[str] = []
    seen_kw: Set[str] = set(); seen_rx: Set[str] = set()
    for kind, val in other_rules:
        if kind == "keyword":
            if val not in seen_kw:
                seen_kw.add(val); kw.append(val)
        elif kind == "regexp":
            if val not in seen_rx:
                seen_rx.add(val); rx.append(val)
    return kw, rx

def build_xray_output(suffixes: Set[str], fulls: Set[str], other_rules: Iterable[Tuple[str, str]]) -> List[str]:
    kw_list, rx_list = dedup_other_rules(other_rules)
    items: List[Tuple[str, str]] = []
    items += [(b, "full") for b in fulls]
    items += [(b, "domain") for b in suffixes]
    items += [(v, "keyword") for v in kw_list]
    items += [(v, "regexp") for v in rx_list]
    rank = {"full": 0, "domain": 1, "keyword": 2, "regexp": 3}
    def key(t: Tuple[str, str]) -> Tuple[int, int, str]:
        val, kind = t
        return (rank.get(kind, 99), label_count(val), val)
    items.sort(key=key)
    out: List[str] = []
    for val, kind in items:
        if kind == "full":
            out.append(f"full:{val}")
        elif kind == "domain":
            out.append(val)
        elif kind == "keyword":
            out.append(f"keyword:{val}")
        elif kind == "regexp":
            out.append(f"regexp:{val}")
    return out

def _collect_bases_from_tokens(tokens: Iterable[str]) -> List[str]:
    out: List[str] = []
    for tok in tokens:
        base = normalize_domain_base(strip_clean_prefixes(tok))
        if base:
            out.append(base)
    return out

def collect_clean_bases_from_clean(cleaned_lines: Iterable[str]) -> List[str]:
    return _collect_bases_from_tokens(cleaned_lines)

def collect_clean_bases_from_hosts(cleaned_lines: Iterable[str]) -> List[str]:
    out: List[str] = []
    for t in cleaned_lines:
        parts = t.split()
        if len(parts) >= 2 and is_hosts_prefix_token(parts[0]):
            out.extend(_collect_bases_from_tokens(parts[1:]))
    return out

def take_until_attr(text: str) -> str:
    parts = text.strip().split()
    keep: List[str] = []
    for tok in parts:
        if tok.startswith("@"):
            break
        keep.append(tok)
    return " ".join(keep).strip()

def parse_xray_file_recursive(path: str, visited: Set[str]) -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
    abspath = os.path.abspath(path)
    if abspath in visited:
        return [], [], []
    if not os.path.exists(abspath):
        print(f"include not found: {path}", file=sys.stderr); sys.exit(2)
    visited.add(abspath)
    base_dir = os.path.dirname(abspath)
    suffix_bases: List[str] = []
    full_bases: List[str] = []
    other_rules: List[Tuple[str, str]] = []
    for line in clean_stream(read_lines(abspath)):
        if line.startswith("include:"):
            inc = take_until_attr(line[len("include:"):])
            inc_path = os.path.join(base_dir, inc)
            p2, e2, o2 = parse_xray_file_recursive(inc_path, visited)
            suffix_bases.extend(p2); full_bases.extend(e2); other_rules.extend(o2); continue
        if line.startswith("keyword:"):
            val = take_until_attr(line[len("keyword:"):])
            if val: other_rules.append(("keyword", val)); continue
        if line.startswith("regexp:"):
            val = take_until_attr(line[len("regexp:"):])
            if val: other_rules.append(("regexp", val)); continue
        if line.startswith("full:"):
            val = take_until_attr(line[len("full:"):]); base = normalize_domain_base(val)
            if base: full_bases.append(base); continue
        if line.startswith("domain:"):
            val = take_until_attr(line[len("domain:"):]); base = normalize_domain_base(val)
            if base: suffix_bases.append(base); continue
        bare = take_until_attr(line); base = normalize_domain_base(bare)
        if base: suffix_bases.append(base)
    return suffix_bases, full_bases, other_rules

def domains_from_hosts(cleaned: Iterable[str], target: str) -> List[str]:
    bases = collect_clean_bases_from_hosts(cleaned)
    entries = [("suffix", b) for b in bases] if target == "suffix" else [("full", b) for b in bases]
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_clean(cleaned: Iterable[str], target: str) -> List[str]:
    bases = collect_clean_bases_from_clean(cleaned)
    entries = [("suffix", b) for b in bases] if target == "suffix" else [("full", b) for b in bases]
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_mihomo(cleaned: Iterable[str]) -> List[str]:
    entries: List[Tuple[str, str]] = []
    for t in cleaned:
        kind, base = split_leading_marker_mihomo(t)
        if not base:
            continue
        if kind == "suffix":
            b2 = _remove_wild_labels(base)
            if b2:
                entries.append(("suffix", b2))
            continue
        if kind == "exact":
            if "*" in base:
                b2 = _remove_wild_labels(base)
                if b2:
                    entries.append(("suffix", b2))
            else:
                entries.append(("full", base))
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_xray(path: str) -> List[str]:
    suffix_bases, full_bases, other_rules = parse_xray_file_recursive(path, set())
    entries: List[Tuple[str, str]] = []
    entries.extend(("suffix", b) for b in suffix_bases)
    entries.extend(("full", b) for b in full_bases)
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, other_rules)

class _IPTrieNode:
    __slots__ = ("z", "o", "covered")
    def __init__(self):
        self.z: _IPTrieNode | None = None
        self.o: _IPTrieNode | None = None
        self.covered: bool = False

def _insert_network(root: _IPTrieNode, net: ipaddress._BaseNetwork) -> None:
    node = root
    nint = int(net.network_address)
    plen = net.prefixlen
    total = net.max_prefixlen
    for i in range(plen):
        bit = (nint >> (total - 1 - i)) & 1
        if bit == 0:
            if node.z is None:
                node.z = _IPTrieNode()
            node = node.z
        else:
            if node.o is None:
                node.o = _IPTrieNode()
            node = node.o
        if node.covered:
            return
    node.covered = True
    node.z = None
    node.o = None

def _compress_collect(node: _IPTrieNode, prefix_int: int, depth: int, acc: List[Tuple[int, int]]) -> bool:
    if node is None:
        return False
    if node.covered:
        acc.append((prefix_int, depth))
        return True
    zl = _compress_collect(node.z, prefix_int << 1, depth + 1, acc)
    ol = _compress_collect(node.o, (prefix_int << 1) | 1, depth + 1, acc)
    if zl and ol:
        acc.pop()
        acc.pop()
        acc.append((prefix_int, depth))
        node.covered = True
        node.z = None
        node.o = None
        return True
    return False

def _trie_aggregate(networks: List[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    v4_root = _IPTrieNode()
    v6_root = _IPTrieNode()
    for n in networks:
        if n.version == 4:
            _insert_network(v4_root, n)
        else:
            _insert_network(v6_root, n)
    out: List[ipaddress._BaseNetwork] = []
    tmp: List[Tuple[int, int]] = []

    tmp.clear()
    _compress_collect(v4_root, 0, 0, tmp)
    for pfx_int, plen in tmp:
        out.append(ipaddress.IPv4Network((pfx_int << (32 - plen), plen)))

    tmp.clear()
    _compress_collect(v6_root, 0, 0, tmp)
    for pfx_int, plen in tmp:
        out.append(ipaddress.IPv6Network((pfx_int << (128 - plen), plen)))

    out.sort(key=lambda n: (n.version, n.prefixlen, int(n.network_address)))
    return out

def _parse_ip_line_to_networks(t: str) -> List[ipaddress._BaseNetwork]:
    m = _RANGE_RE.match(t)
    if m:
        try:
            a = ipaddress.ip_address(m.group(1))
            b = ipaddress.ip_address(m.group(2))
        except ValueError:
            return []
        if a.version != b.version:
            return []
        if int(a) > int(b):
            a, b = b, a
        return list(ipaddress.summarize_address_range(a, b))
    try:
        return [ipaddress.ip_network(t, strict=False)]
    except ValueError:
        return []

def parse_ips_to_cidrs(path: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    seen: Set[Tuple[int, int, int]] = set()
    for raw in clean_stream(read_lines(path)):
        for n in _parse_ip_line_to_networks(raw.strip()):
            key = (n.version, int(n.network_address), n.prefixlen)
            if key in seen:
                continue
            seen.add(key)
            nets.append(n)
    if not nets:
        return []
    return _trie_aggregate(nets)

def cmd_domains(src: str, dst: str, input_type: str, target: str) -> None:
    if input_type in ("mihomo", "xray"):
        if target != "preserve":
            print("for input-type mihomo/xray only --target preserve is allowed", file=sys.stderr); sys.exit(2)
        if input_type == "mihomo":
            cleaned = list(clean_stream(read_lines(src)))
            write_text_lines(dst, domains_from_mihomo(cleaned)); return
        write_text_lines(dst, domains_from_xray(src)); return
    if input_type in ("clean", "hosts"):
        if target not in ("suffix", "exact"):
            print("for input-type clean/hosts only --target suffix or --target exact are allowed", file=sys.stderr); sys.exit(2)
        cleaned = list(clean_stream(read_lines(src)))
        if input_type == "clean":
            write_text_lines(dst, domains_from_clean(cleaned, target)); return
        write_text_lines(dst, domains_from_hosts(cleaned, target)); return
    print("unknown input type", file=sys.stderr); sys.exit(2)

def cmd_ips(src: str, dst: str) -> None:
    nets = parse_ips_to_cidrs(src)
    items = [f"{n.network_address}/{n.prefixlen}" for n in nets]
    write_text_lines(dst, items)

def main() -> None:
    p = argparse.ArgumentParser(prog="tool", description="Domain/IP list optimizer and converter (XRAY output)")
    sub = p.add_subparsers(dest="mode", required=True)
    p_dom = sub.add_parser("domains", help="Process domain lists; output: XRAY (domain/full/keyword/regexp)")
    p_dom.add_argument("src", help="Input file")
    p_dom.add_argument("dst", help="Output .list path")
    p_dom.add_argument("--input-type", choices=["hosts", "clean", "mihomo", "xray"], required=True)
    p_dom.add_argument("--target", choices=["suffix", "exact", "preserve"], required=True)
    p_dom.set_defaults(func=lambda a: cmd_domains(a.src, a.dst, a.input_type, a.target))
    p_ip = sub.add_parser("ips", help="Process IP/CIDR lists; output: CIDR")
    p_ip.add_argument("src", help="Input file")
    p_ip.add_argument("dst", help="Output .list path")
    p_ip.set_defaults(func=lambda a: cmd_ips(a.src, a.dst))
    args = p.parse_args()
    if args.mode == "ips":
        cmd_ips(args.src, args.dst)
    else:
        args.func(args)

if __name__ == "__main__":
    main()