"""Remove only this workspace's disposable downloads and local test databases."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
assert (root / 'client/Cargo.toml').is_file()
assert (root / 'primitives/Cargo.toml').is_file()
for relative in ('.cache', 'artifacts/network/data'):
    directory = root / relative
    if directory.is_symlink() or not directory.resolve().is_relative_to(root):
        raise SystemExit('Refusing cleanup outside the workspace: ' + str(directory))
    if directory.exists():
        shutil.rmtree(directory)
        print('Removed ' + str(directory))
