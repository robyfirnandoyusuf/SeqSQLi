"""
bypass_lab/run_all.py
=====================
Run all bypass test modules and print a consolidated summary.

Usage:
    python3 bypass_lab/run_all.py            # all modules
    python3 bypass_lab/run_all.py http       # only test_http
    python3 bypass_lab/run_all.py mysql      # only test_mysql
    python3 bypass_lab/run_all.py encoding   # only test_encoding
    python3 bypass_lab/run_all.py parser     # only test_parser
"""
import sys, importlib
sys.path.insert(0, '/mnt/d/Kuliah/RL/SeqSQLi')

MODULES = {
    "http":     "bypass_lab.test_http",
    "mysql":    "bypass_lab.test_mysql",
    "encoding": "bypass_lab.test_encoding",
    "parser":   "bypass_lab.test_parser",
}

def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else list(MODULES.keys())
    for key in targets:
        if key not in MODULES:
            print(f"Unknown module: {key}. Options: {list(MODULES.keys())}")
            continue
        mod = importlib.import_module(MODULES[key])
        # Each module runs its tests in __main__ block
        # Re-trigger by calling the test functions directly
        fns = [v for k, v in vars(mod).items() if k.startswith("test_") or k.startswith("cases_")]
        print(f"\n{'#'*60}")
        print(f"# Running: {key}")
        print(f"{'#'*60}")
        if hasattr(mod, "__file__"):
            import runpy
            runpy.run_module(MODULES[key], run_name="__main__", alter_sys=False)

if __name__ == "__main__":
    main()
