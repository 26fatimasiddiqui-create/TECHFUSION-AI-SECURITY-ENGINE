#!/usr/bin/env python3
"""
ThreatFusion — Autonomous AI Security & Risk Correlation Platform
Unified Runner Script: Starts FastAPI backend & Vite frontend, opens web browser, and handles clean shutdown.
"""

import os
import sys
import time
import shutil
import signal
import urllib.request
import webbrowser
import subprocess
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE = ROOT_DIR / ".env.example"

# ANSI Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_colored(text: str, color: str = ""):
    print(f"{color}{text}{RESET}")


def check_and_setup_env():
    """Ensure .env exists in the root directory."""
    if not ENV_FILE.exists() and ENV_EXAMPLE.exists():
        print_colored("[INFO] Creating root .env from .env.example...", CYAN)
        shutil.copyfile(ENV_EXAMPLE, ENV_FILE)


def check_python_dependencies():
    """Verify required Python packages are installed."""
    required_packages = ["fastapi", "uvicorn", "pydantic", "pydantic_settings", "httpx"]
    missing = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print_colored(f"[WARN] Missing Python packages: {', '.join(missing)}", YELLOW)
        print_colored("[INFO] Installing dependencies from requirements.txt...", CYAN)
        req_file = ROOT_DIR / "requirements.txt"
        if req_file.exists():
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)], check=True)
            print_colored("[SUCCESS] Python dependencies installed.", GREEN)


def check_frontend_dependencies():
    """Verify frontend node_modules exist, or run npm install."""
    node_modules = FRONTEND_DIR / "node_modules"
    if not node_modules.exists():
        print_colored("[INFO] frontend/node_modules not found. Running npm install...", CYAN)
        npm_cmd = shutil.which("npm") or shutil.which("npm.cmd") or "npm"
        subprocess.run([npm_cmd, "install"], cwd=str(FRONTEND_DIR), check=True)
        print_colored("[SUCCESS] Frontend dependencies installed.", GREEN)


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a network port is already open or bound by a process."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def wait_for_service(url: str, timeout_sec: int = 30) -> bool:
    """Wait until a service responds at url."""
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RunnerHealthCheck"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status in (200, 304, 404):
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def kill_process_tree(proc: subprocess.Popen):
    """Cleanly terminate a process and its child processes."""
    if proc is None or proc.poll() is not None:
        return

    pid = proc.pid
    if sys.platform == "win32":
        try:
            # taskkill /F /T terminates process and all child processes created by it
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            proc.kill()
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            proc.terminate()


def main():
    # Enable ANSI escape sequences on Windows CMD
    if sys.platform == "win32":
        os.system("")

    print()
    print_colored("================================================================", CYAN)
    print_colored("   PS-8 Security Monitoring & Risk Analysis Platform Runner     ", BOLD + CYAN)
    print_colored("================================================================", CYAN)
    print()

    # Step 1: Environment & dependency checks
    check_and_setup_env()
    check_python_dependencies()
    check_frontend_dependencies()

    # Step 2: Start Backend (FastAPI via Uvicorn) if not already running
    backend_proc = None
    if is_port_in_use(8000) or wait_for_service("http://127.0.0.1:8000/health", timeout_sec=1):
        print_colored("[INFO] Backend is already running on http://127.0.0.1:8000", GREEN)
    else:
        print_colored("[1/2] Starting FastAPI Backend on http://127.0.0.1:8000...", CYAN)
        backend_env = os.environ.copy()
        backend_env["PYTHONUNBUFFERED"] = "1"

        backend_kwargs = {}
        if sys.platform != "win32":
            backend_kwargs["preexec_fn"] = os.setsid

        backend_cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--reload"
        ]
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(ROOT_DIR),
            env=backend_env,
            **backend_kwargs
        )

    # Step 3: Start Frontend (Vite) if not already running
    frontend_proc = None
    if is_port_in_use(3000) or wait_for_service("http://localhost:3000", timeout_sec=1):
        print_colored("[INFO] Frontend is already running on http://localhost:3000", GREEN)
    else:
        print_colored("[2/2] Starting Vite Frontend on http://localhost:3000...", CYAN)
        npm_cmd = shutil.which("npm") or shutil.which("npm.cmd") or "npm"
        frontend_kwargs = {}
        if sys.platform != "win32":
            frontend_kwargs["preexec_fn"] = os.setsid

        frontend_proc = subprocess.Popen(
            [npm_cmd, "run", "dev"],
            cwd=str(FRONTEND_DIR),
            **frontend_kwargs
        )

    # Step 4: Wait for services to be ready
    print_colored("[WAIT] Verifying servers are healthy and responding...", YELLOW)
    backend_ready = wait_for_service("http://127.0.0.1:8000/api/health", timeout_sec=20)
    frontend_ready = wait_for_service("http://localhost:3000", timeout_sec=20)

    print()
    print_colored("================================================================", GREEN)
    print_colored("   ThreatFusion Security Platform is Running!                  ", BOLD + GREEN)
    print_colored("   Tagline: Secure Today • Stronger Tomorrow                   ", CYAN)
    print_colored("================================================================", GREEN)
    print_colored(f"   * Web Dashboard:   {BOLD}http://localhost:3000{RESET}", GREEN)
    print_colored(f"   * Backend API:     {BOLD}http://127.0.0.1:8000{RESET}", GREEN)
    print_colored(f"   * Swagger Docs:    {BOLD}http://127.0.0.1:8000/docs{RESET}", GREEN)
    print_colored(f"   * Health Status:   {BOLD}http://127.0.0.1:8000/api/health{RESET}", GREEN)
    print_colored("================================================================", GREEN)
    print_colored("   Opening Web Dashboard in your default browser...", CYAN)
    print_colored("   Press Ctrl+C anytime to stop both servers.", YELLOW)
    print_colored("================================================================", GREEN)
    print()

    # Step 5: Automatically open the browser
    webbrowser.open("http://localhost:3000")

    # Step 6: Monitor processes until interrupted
    try:
        while True:
            if backend_proc and backend_proc.poll() is not None:
                print_colored("\n[ERROR] Backend process terminated unexpectedly.", RED)
                break
            if frontend_proc and frontend_proc.poll() is not None:
                print_colored("\n[ERROR] Frontend process terminated unexpectedly.", RED)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print_colored("\n[INFO] Shutdown signal received (Ctrl+C). Stopping servers...", YELLOW)
    finally:
        print_colored("[INFO] Cleaning up processes...", CYAN)
        if backend_proc:
            kill_process_tree(backend_proc)
        if frontend_proc:
            kill_process_tree(frontend_proc)
        print_colored("[SUCCESS] All servers stopped cleanly.", GREEN)


if __name__ == "__main__":
    main()
