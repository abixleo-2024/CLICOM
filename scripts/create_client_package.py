import shutil
import zipfile
from pathlib import Path

root = Path(r"C:\Users\Abishek\.gemini\antigravity\scratch\clicom")
dist = root / "dist_client"
if dist.exists():
    shutil.rmtree(dist)
dist.mkdir(parents=True)

# 1. Copy client code
shutil.copytree(root / "client", dist / "client")

# 2. Copy certs/ca.crt
(dist / "certs").mkdir()
shutil.copy2(root / "certs" / "ca.crt", dist / "certs" / "ca.crt")

# 3. Copy compiled engine dll
engine_dll = root / "build" / "windows-ninja-debug" / "engine" / "libclicom_engine.dll"
shutil.copy2(engine_dll, dist / "libclicom_engine.dll")
# Also place inside client/ for automatic discovery
shutil.copy2(engine_dll, dist / "client" / "libclicom_engine.dll")

# 4. Copy runtime dependencies from ucrt64 so Laptop B/C don't need MSYS2 installed
ucrt_bin = Path(r"C:\msys64\ucrt64\bin")
dll_deps = ["libcrypto-3-x64.dll", "libssl-3-x64.dll", "libopus-0.dll"]
for d in dll_deps:
    src_dll = ucrt_bin / d
    if src_dll.is_file():
        shutil.copy2(src_dll, dist / d)
        shutil.copy2(src_dll, dist / "client" / d)

# 5. Create start_client.bat
bat_content = """@echo off
set SERVER_IP=%1
set NODE_NAME=%2
set PORT=%3
if "%SERVER_IP%"=="" set SERVER_IP=127.0.0.1
if "%NODE_NAME%"=="" set NODE_NAME=OPERATOR-NODE
if "%PORT%"=="" set PORT=8443

echo ========================================================
echo  CLICOM Tactical Client - Connecting to %SERVER_IP%:%PORT%
echo ========================================================
pip install textual >nul 2>&1
python -m client.cli -s %SERVER_IP% -p %PORT% --ca-cert certs/ca.crt -n %NODE_NAME%
pause
"""
with open(dist / "start_client.bat", "w", encoding="utf-8") as f:
    f.write(bat_content)

# 6. Create ZIP archive
zip_path = root / "clicom-client.zip"
if zip_path.exists():
    zip_path.unlink()

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for file in dist.rglob("*"):
        if file.is_file():
            arcname = file.relative_to(dist)
            zf.write(file, arcname)

print(f"Created standalone client package: {zip_path} ({zip_path.stat().st_size / 1024:.1f} KB)")
