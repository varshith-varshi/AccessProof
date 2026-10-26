"""Runner enrollment client. It deliberately exposes no remote shell surface."""

from __future__ import annotations

import httpx
import socket
import subprocess

from apps.runner.accessproof_runner.config import (
    RunnerCredentials,
    capabilities,
    host_platform,
    save_credentials,
)


def enroll(*, api_url: str, enrollment_code: str, name: str, version: str) -> RunnerCredentials:
    platform_name, architecture = host_platform()
    response = httpx.post(
        f"{api_url.rstrip('/')}/api/v1/runners/exchange",
        json={
            "registration_token": enrollment_code.strip(),
            "name": name.strip(),
            "version": version,
            "platform": platform_name,
            "architecture": architecture,
            "capabilities": capabilities(),
        },
        timeout=30,
    )
    if response.status_code >= 400:
        raise RuntimeError("Unable to connect this runner to AccessProof. Check the server and enrollment code.")
    payload = response.json()
    credentials = RunnerCredentials(
        api_url=api_url.rstrip("/"),
        runner_id=payload["runner_id"],
        runner_secret=payload["runner_secret"],
        name=name.strip(),
        version=version,
    )
    save_credentials(credentials)
    return credentials


def launch_enrollment_ui(version: str) -> None:
    """A small local enrollment screen. No cloud-issued commands are executed."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("AccessProof Runner")
    root.resizable(False, False)
    body = ttk.Frame(root, padding=24)
    body.grid()
    ttk.Label(body, text="AccessProof Runner", font=("Sans", 16, "bold")).grid(column=0, row=0, columnspan=2, sticky="w")
    ttk.Label(body, text="Connect this machine to your AccessProof workspace.").grid(column=0, row=1, columnspan=2, pady=(4, 18), sticky="w")
    ttk.Label(body, text="Server").grid(column=0, row=2, sticky="w")
    server = ttk.Entry(body, width=42)
    server.insert(0, "https://api.accessproof.ai")
    server.grid(column=0, row=3, columnspan=2, pady=(2, 12), sticky="ew")
    ttk.Label(body, text="Enrollment code").grid(column=0, row=4, sticky="w")
    code = ttk.Entry(body, width=42)
    code.grid(column=0, row=5, columnspan=2, pady=(2, 12), sticky="ew")
    ttk.Label(body, text="Runner name").grid(column=0, row=6, sticky="w")
    name = ttk.Entry(body, width=42)
    name.insert(0, socket.gethostname())
    name.grid(column=0, row=7, columnspan=2, pady=(2, 16), sticky="ew")
    status = ttk.Label(body, text="Not connected")
    status.grid(column=0, row=9, columnspan=2, sticky="w")

    def connect() -> None:
        button.state(["disabled"])
        status.configure(text="Connecting…")
        root.update_idletasks()
        try:
            credentials = enroll(api_url=server.get(), enrollment_code=code.get(), name=name.get(), version=version)
            subprocess.run(["systemctl", "enable", "--now", "accessproof-runner.service"], check=False, capture_output=True)
            status.configure(text=f"Connected as {credentials.name}. The runner service is starting.")
            messagebox.showinfo("AccessProof Runner", "Runner connected successfully.")
        except Exception:
            status.configure(text="Unable to connect this runner. Check the server and enrollment code.")
            messagebox.showerror("AccessProof Runner", "Unable to connect this runner. Check the server and enrollment code.")
        finally:
            button.state(["!disabled"])

    button = ttk.Button(body, text="Connect Runner", command=connect)
    button.grid(column=0, row=8, pady=(0, 12), sticky="w")
    root.mainloop()
