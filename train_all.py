"""
train_all.py
------------
Convenience script: trains both Module A (spam/ham) and Module B (malicious
URL) in one go.

Run from the project root:
    python train_all.py
"""

import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))


def run(cmd):
    print(f"\n{'='*70}\n> {' '.join(cmd)}\n{'='*70}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        sys.exit(result.returncode)


if __name__ == "__main__":
    run([sys.executable, os.path.join("src", "train_spam_model.py")])
    run([sys.executable, os.path.join("src", "train_url_model.py"), "--sample-size", "60000"])
    print("\nBoth models trained successfully. You can now run: python app.py")
