#!/usr/bin/env python3
"""Apply privacy redaction to existing skill_eval_*.json result files.

This is a one-shot migration that mirrors the redaction the live harness now
applies at write time. It:

- Strips any field containing 'api_key' anywhere in meta.
- Replaces local `candidate_base_url` / `judge_base_url` / lmstudio URL fields
  with sha256 tags (public hosts on the allowlist are kept verbatim).
- Replaces `skill_root`, `docker_host_working_folder`, and
  `suite_config_path` with just the basename, recording the sha256 of the
  full original path alongside.
- Back-fills `loaded_skill_file_hashes` from the current repository state,
  marking the source as `post-hoc-from-current-repo` so migrated runs are
  distinguishable from runs that hashed at execution time.

Run from the repo root:

    python utilities/redact_skill_eval_results.py
    python utilities/redact_skill_eval_results.py --dry-run
    python utilities/redact_skill_eval_results.py --results-dir skills/evaluation/results

By default `.bak` backups are written next to each modified file. Pass
`--no-backup` to skip them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from utilities.skill_eval_harness import (  # noqa: E402  (sys.path tweak above)
    _slugify,
    _sha256_tag,
    compute_skill_file_hashes,
    redact_meta_for_output,
)


DEFAULT_RESULTS_DIR = REPO_ROOT / "skills" / "evaluation" / "results"
FILENAME_STAMP_RE = re.compile(r"^skill_eval_(\d{8}T\d{6}Z)(?:_(.+))?$")


def _read_skill_file_contents(loaded_paths: list[str]) -> tuple[dict[str, str], list[str]]:
    """Read current repo contents for the given relative skill paths.

    Returns (contents_by_path, missing_paths). Paths that cannot be read are
    skipped and reported in missing_paths.
    """
    contents: dict[str, str] = {}
    missing: list[str] = []
    for rel_path in loaded_paths:
        if not isinstance(rel_path, str) or not rel_path:
            continue
        candidate = REPO_ROOT / rel_path
        if not candidate.is_file():
            missing.append(rel_path)
            continue
        try:
            contents[rel_path] = candidate.read_text(encoding="utf-8")
        except OSError:
            missing.append(rel_path)
    return contents, missing


def _already_redacted(meta: dict) -> bool:
    return bool(meta.get("redaction_version"))


def _safe_filename_suffix(meta: dict) -> str | None:
    """Build the new (path-free) filename suffix from a redacted meta block.

    Returns None when meta lacks the fields needed to construct it.
    """
    run_idx = meta.get("run_index")
    candidate_label = meta.get("candidate_label")
    skill_root_hash = meta.get("skill_root_sha256")
    if run_idx is None or not candidate_label or not isinstance(skill_root_hash, str):
        return None
    digest = skill_root_hash.split(":", 1)[-1]
    if not digest:
        return None
    try:
        idx_str = f"{int(run_idx):02d}"
    except (TypeError, ValueError):
        return None
    return f"{idx_str}_{_slugify(str(candidate_label))}_skill-{digest[:12]}"


def _plan_rename(path: Path, meta: dict) -> Path | None:
    """Return a new path for `path` if its filename leaks a local path slug.

    The current filename format is
    `skill_eval_<stamp>[_<suffix>].json`. We rewrite the suffix to the
    hash-based form whenever the on-disk name doesn't already match it.
    """
    stem_match = FILENAME_STAMP_RE.match(path.stem)
    if not stem_match:
        return None
    stamp, current_suffix = stem_match.group(1), stem_match.group(2) or ""
    new_suffix = _safe_filename_suffix(meta)
    if new_suffix is None:
        return None
    if current_suffix == new_suffix:
        return None
    new_name = f"skill_eval_{stamp}_{new_suffix}{path.suffix}"
    return path.with_name(new_name)


def migrate_file(path: Path, *, dry_run: bool, make_backup: bool) -> dict:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    meta = data.get("meta")
    if not isinstance(meta, dict):
        return {"path": str(path), "status": "skipped", "reason": "no meta block"}

    actions: list[str] = []
    if _already_redacted(meta):
        actions.append("already-redacted")

    # Back-fill SKILL.md hashes from current repo state if not already present.
    if "loaded_skill_file_hashes" not in meta:
        loaded_paths = meta.get("loaded_skill_files") or []
        if isinstance(loaded_paths, list):
            contents, missing = _read_skill_file_contents(loaded_paths)
            hashes = compute_skill_file_hashes(contents)
            meta["loaded_skill_file_hashes"] = hashes
            meta["loaded_skill_file_hashes_source"] = "post-hoc-from-current-repo"
            if missing:
                meta["loaded_skill_file_hashes_missing"] = missing
            actions.append(f"hashes:{len(hashes)} missing:{len(missing)}")

    # Apply URL / path / api_key redaction in place.
    data["meta"] = redact_meta_for_output(meta)
    actions.append("redacted")

    new_text = json.dumps(data, indent=2, ensure_ascii=False)
    content_changed = new_text != raw

    rename_target = _plan_rename(path, data["meta"])
    if rename_target is not None:
        actions.append(f"rename->{rename_target.name}")

    if not content_changed and rename_target is None:
        return {"path": str(path), "status": "unchanged", "actions": actions}

    if dry_run:
        return {"path": str(path), "status": "would-write", "actions": actions}

    if content_changed:
        if make_backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            if not backup_path.exists():
                backup_path.write_text(raw, encoding="utf-8")
        path.write_text(new_text, encoding="utf-8")

    written_path = path
    if rename_target is not None:
        if rename_target.exists():
            # Refuse to clobber an unrelated file.
            actions.append(f"rename-skipped:target-exists")
        else:
            path.rename(rename_target)
            # Move the .bak alongside the renamed file so audits stay paired.
            old_bak = path.with_suffix(path.suffix + ".bak")
            if old_bak.exists():
                new_bak = rename_target.with_suffix(rename_target.suffix + ".bak")
                if not new_bak.exists():
                    old_bak.rename(new_bak)
            written_path = rename_target

    return {"path": str(written_path), "status": "written", "actions": actions}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR,
                   help="Directory containing skill_eval_*.json files.")
    p.add_argument("--pattern", default="skill_eval_*.json",
                   help="Glob pattern for result files (default: skill_eval_*.json).")
    p.add_argument("--dry-run", action="store_true", help="Report changes without writing.")
    p.add_argument("--no-backup", dest="backup", action="store_false",
                   help="Do not write .bak files next to each modified result.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    results_dir: Path = args.results_dir
    if not results_dir.is_dir():
        print(f"[error] results directory not found: {results_dir}", file=sys.stderr)
        return 2
    files = sorted(results_dir.rglob(args.pattern))
    if not files:
        print(f"[info] no files matched {args.pattern} in {results_dir}")
        return 0

    written = 0
    for f in files:
        try:
            result = migrate_file(f, dry_run=args.dry_run, make_backup=args.backup)
        except json.JSONDecodeError as exc:
            print(f"[error] {f}: invalid JSON: {exc}", file=sys.stderr)
            continue
        status = result["status"]
        actions = ",".join(result.get("actions", []))
        print(f"[{status:>11}] {f.name} ({actions})")
        if status == "written":
            written += 1

    print(f"\n{'(dry-run) ' if args.dry_run else ''}Done. Files modified: {written}/{len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
