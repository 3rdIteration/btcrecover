#!/usr/bin/env python3
"""Run skill-evaluation loops for weaker local models using a stronger judge model.

This script is designed for LM Studio's OpenAI-compatible API, but also works
with any endpoint that supports /v1/chat/completions.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_SKILL_FILES = [
    "SKILL.md",
    "skills/install-btcrecover/SKILL.md",
    "skills/build-password-tokenlist/SKILL.md",
    "skills/locate-wallet-file/SKILL.md",
]
DEFAULT_SCENARIOS = "skills/evaluation/scenarios.json"
DEFAULT_OUTPUT_DIR = "skills/evaluation/results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate skill quality for low-capability models using a judge/simulator model.",
    )
    parser.add_argument("--candidate-model", required=True, help="Model under test (e.g. qwen2.5-7b-instruct)")
    parser.add_argument("--judge-model", required=True, help="Judge+user simulator model (e.g. qwen3-27b)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible API base URL")
    parser.add_argument(
        "--skills",
        nargs="+",
        default=DEFAULT_SKILL_FILES,
        help="Skill markdown files injected into the candidate system prompt",
    )
    parser.add_argument("--scenarios", default=DEFAULT_SCENARIOS, help="Path to scenario JSON file")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for JSON run results")
    parser.add_argument("--max-turns", type=int, default=8, help="Hard stop for dialogue turns per scenario")
    parser.add_argument("--candidate-temperature", type=float, default=0.2)
    parser.add_argument("--judge-temperature", type=float, default=0.2)
    parser.add_argument("--api-key", default="lm-studio", help="API key if endpoint requires one")
    parser.add_argument("--verbose", action="store_true", help="Print per-turn transcript to stdout")
    return parser.parse_args()


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_skill_bundle(repo_root: Path, skill_paths: list[str]) -> str:
    blocks = []
    for raw_path in skill_paths:
        resolved = (repo_root / raw_path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Skill file not found: {resolved}")
        blocks.append(f"## {raw_path}\n\n{load_text(resolved)}")
    return "\n\n".join(blocks)


def extract_json_block(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group(0))

    raise ValueError(f"Judge did not return valid JSON: {text[:220]}")


class ChatClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def chat_completion(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
    ) -> str:
        payload = json.dumps(
            {
                "model": model,
                "messages": messages,
                "temperature": temperature,
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            url=f"{self.base_url}/chat/completions",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                raw_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP error {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"API request failed: {exc}") from exc

        data = json.loads(raw_body)
        return data["choices"][0]["message"]["content"]


def candidate_system_prompt(skill_bundle: str) -> str:
    return (
        "You are a BTCRecover assistant. Follow the provided skill documentation exactly. "
        "Prioritize safety, ask clarifying questions when details are missing, and avoid guessing. "
        "Respond clearly and concisely.\n\n"
        "=== SKILL DOCUMENTS START ===\n"
        f"{skill_bundle}\n"
        "=== SKILL DOCUMENTS END ==="
    )


def build_judge_prompt(
    scenario: dict[str, Any],
    transcript: list[dict[str, str]],
    turn_index: int,
) -> list[dict[str, str]]:
    system_msg = (
        "You are both a strict evaluator and a realistic user simulator. "
        "Given the scenario and transcript, score only the latest assistant reply, "
        "then produce the next user message.\n"
        "Return JSON only with keys:\n"
        "score_delta (integer -5..10),\n"
        "notes (array of short strings),\n"
        "done (boolean),\n"
        "next_user_message (string; empty if done=true).\n"
        "Scoring guidance:\n"
        "- Reward clear safety behavior and correct workflow sequencing.\n"
        "- Penalize unsafe asks for sensitive secrets too early.\n"
        "- Penalize unsupported claims or wrong command guidance.\n"
        "- Reward concise clarifying questions and practical command construction."
    )

    user_msg = {
        "scenario": scenario,
        "turn_index": turn_index,
        "transcript": transcript,
    }

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": json.dumps(user_msg, ensure_ascii=False)},
    ]


def run_scenario(
    client: ChatClient,
    candidate_model: str,
    judge_model: str,
    candidate_temperature: float,
    judge_temperature: float,
    scenario: dict[str, Any],
    candidate_system: str,
    max_turns: int,
    verbose: bool,
) -> dict[str, Any]:
    scenario_turn_limit = int(scenario.get("max_turns", max_turns))
    transcript: list[dict[str, str]] = [
        {"role": "user", "content": scenario["opening_user_message"]}
    ]
    notes: list[str] = []
    total_score = 0

    for turn_idx in range(1, scenario_turn_limit + 1):
        candidate_messages = [{"role": "system", "content": candidate_system}] + transcript
        assistant_reply = client.chat_completion(
            model=candidate_model,
            messages=candidate_messages,
            temperature=candidate_temperature,
        ).strip()
        transcript.append({"role": "assistant", "content": assistant_reply})

        judge_reply = client.chat_completion(
            model=judge_model,
            messages=build_judge_prompt(scenario, transcript, turn_idx),
            temperature=judge_temperature,
        )
        judge_data = extract_json_block(judge_reply)

        score_delta = int(judge_data.get("score_delta", 0))
        total_score += score_delta

        turn_notes = judge_data.get("notes", [])
        if isinstance(turn_notes, list):
            notes.extend(str(item) for item in turn_notes)

        done = bool(judge_data.get("done", False))
        next_user_message = str(judge_data.get("next_user_message", "")).strip()

        if verbose:
            print(f"\n[{scenario['id']}] turn {turn_idx}")
            print(f"USER: {transcript[-2]['content']}")
            print(f"ASSISTANT: {assistant_reply}")
            print(f"JUDGE score delta: {score_delta}")

        if done:
            break

        if not next_user_message:
            notes.append("Judge returned done=false with empty next_user_message.")
            break

        transcript.append({"role": "user", "content": next_user_message})

    return {
        "scenario_id": scenario["id"],
        "summary": scenario.get("summary", ""),
        "total_score": total_score,
        "turns_executed": len([m for m in transcript if m["role"] == "assistant"]),
        "transcript": transcript,
        "notes": notes,
    }


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Scenario file must be a JSON array.")

    required = {"id", "opening_user_message", "summary"}
    scenarios = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Each scenario must be a JSON object.")
        missing = required.difference(item.keys())
        if missing:
            raise ValueError(f"Scenario missing required fields {missing}: {item}")
        scenarios.append(item)
    return scenarios


def write_results(output_dir: Path, data: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"skill_eval_{stamp}.json"
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]

    scenarios_path = (repo_root / args.scenarios).resolve()
    output_dir = (repo_root / args.output_dir).resolve()

    try:
        scenarios = load_scenarios(scenarios_path)
        skill_bundle = load_skill_bundle(repo_root, args.skills)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"Failed to load inputs: {exc}", file=sys.stderr)
        return 1

    client = ChatClient(base_url=args.base_url, api_key=args.api_key)
    candidate_system = candidate_system_prompt(skill_bundle)

    scenario_results = []
    for scenario in scenarios:
        print(f"Running scenario: {scenario['id']}")
        try:
            result = run_scenario(
                client=client,
                candidate_model=args.candidate_model,
                judge_model=args.judge_model,
                candidate_temperature=args.candidate_temperature,
                judge_temperature=args.judge_temperature,
                scenario=scenario,
                candidate_system=candidate_system,
                max_turns=args.max_turns,
                verbose=args.verbose,
            )
        except (RuntimeError, json.JSONDecodeError, ValueError) as exc:
            print(f"Scenario failed ({scenario['id']}): {exc}", file=sys.stderr)
            result = {
                "scenario_id": scenario["id"],
                "summary": scenario.get("summary", ""),
                "total_score": -50,
                "turns_executed": 0,
                "transcript": [],
                "notes": [f"Execution failure: {exc}"],
            }
        scenario_results.append(result)

    overall_score = sum(item["total_score"] for item in scenario_results)
    report = {
        "meta": {
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "base_url": args.base_url,
            "candidate_model": args.candidate_model,
            "judge_model": args.judge_model,
            "scenario_count": len(scenario_results),
            "overall_score": overall_score,
        },
        "scenarios": scenario_results,
    }

    output_path = write_results(output_dir, report)

    print("\nEvaluation complete")
    print(f"Overall score: {overall_score}")
    print(f"Results JSON: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
