import pathlib
import subprocess
import sys
import tempfile
import venv

root = pathlib.Path(__file__).resolve().parents[2]
wheel = next((root / "native-dist").glob("*.whl"))
with tempfile.TemporaryDirectory(prefix="ratify-python-consumer-") as directory:
    venv.EnvBuilder(with_pip=True).create(directory)
    python = pathlib.Path(directory) / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", str(wheel)],
        check=True,
    )
    subprocess.run(
        [str(python), "-c", "import ratify_rust_accel; assert callable(ratify_rust_accel.verify_bundle_object)"],
        check=True,
    )
    print(f"clean_install_ok {wheel.name}")
