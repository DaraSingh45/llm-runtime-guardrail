import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "agent_scanner"))
sys.path.insert(0, str(ROOT))
