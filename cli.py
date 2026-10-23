from __future__ import annotations

import argparse
from pathlib import Path
import sys
import threading

from ducapk.runner import (AnalysisCancelled, DEFAULT_GHIDRA_THREADS, ROOT, analyze,
                           set_ghidra_threads)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Analyze Android APKs, including Unity IL2CPP packages")
    parser.add_argument("inputs", nargs="*", type=Path, help="APK, XAPK, APKS, split APKs, or loose binary+metadata")
    parser.add_argument("--output", type=Path, default=ROOT / "output")
    parser.add_argument("--metadata-only", action="store_true", help="Only export class/method metadata, no function bodies")
    parser.add_argument("--resume", type=Path, help="Continue a previous DucAPK job")
    parser.add_argument("--max-methods", type=int, help="Limit decompiled methods (diagnostics)")
    parser.add_argument("--no-level-json", action="store_true",
                        help="Skip scanning Unity level/configuration data")
    parser.add_argument("--category", action="append", choices=("game", "unity", "sdk"),
                        help="IL2CPP group to decompile; repeat for multiple groups (default: game)")
    parser.add_argument("--no-java", action="store_true", dest="no_jadx",
                        help="Skip decompiling Java/DEX (Android SDK code)")
    parser.add_argument("--no-jadx", action="store_true", dest="no_jadx", help=argparse.SUPPRESS)
    parser.add_argument("--native", action="store_true",
                        help="Analyze native C/C++ .so libraries when Unity IL2CPP is absent")
    parser.add_argument("--threads", type=int, default=DEFAULT_GHIDRA_THREADS,
                        help=f"Parallel decompiler threads (default: {DEFAULT_GHIDRA_THREADS})")
    args = parser.parse_args()
    if not args.inputs and not args.resume:
        parser.error("Provide at least one APK/XAPK, or --resume JOB_DIRECTORY")
    set_ghidra_threads(args.threads)
    cancel = threading.Event()
    try:
        job = analyze(args.inputs, args.output, print, cancel,
                      with_ghidra=not args.metadata_only,
                      max_methods=args.max_methods, resume_job=args.resume,
                      include_categories=set(args.category) if args.category else None,
                      extract_levels=not args.no_level_json,
                      decompile_java=not args.no_jadx, decompile_native=args.native)
        print("RESULT:", job)
        return 0
    except KeyboardInterrupt:
        cancel.set()
        print("Đã yêu cầu dừng.")
        return 130
    except AnalysisCancelled as error:
        print(error)
        return 130
    except Exception as error:
        print("LỖI:", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
