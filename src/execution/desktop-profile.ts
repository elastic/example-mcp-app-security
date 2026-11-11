/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runOnTarget } from "./target.js";

const DESKTOP_SERVICE = "atomic-desktop.service";

export const DESKTOP_INSTALLER_SOURCE = String.raw`import os
import pathlib
import pwd
import grp
import secrets
import shutil
import subprocess
import sys

execution_user = sys.argv[1]
run_id = sys.argv[2]
account = pwd.getpwnam(execution_user)
group_name = grp.getgrgid(account.pw_gid).gr_name
required = ["Xvfb", "openbox-session", "x11vnc", "websockify", "firefox", "dbus-run-session", "xdg-settings"]
missing = [name for name in required if shutil.which(name) is None]
if missing:
    raise SystemExit("desktop profile is missing approved packages: " + ", ".join(missing))

desktop_dir = pathlib.Path("/var/tmp/atomic-runs") / run_id / "desktop"
desktop_dir.mkdir(parents=True, exist_ok=True)
os.chown(desktop_dir, account.pw_uid, account.pw_gid)
os.chmod(desktop_dir, 0o700)

password_file = desktop_dir / "vnc-password"
password_file.write_text(secrets.token_urlsafe(18) + "\n", encoding="utf-8")
os.chown(password_file, account.pw_uid, account.pw_gid)
os.chmod(password_file, 0o600)

launcher = desktop_dir / "launch-desktop.sh"
launcher.write_text("""#!/usr/bin/env bash
set -euo pipefail
export DISPLAY=:99
export HOME={home}
/usr/bin/Xvfb :99 -screen 0 1440x900x24 -nolisten tcp &
sleep 2
/usr/bin/openbox-session &
/usr/bin/x11vnc -display :99 -localhost -forever -shared -passwdfile {password_file} &
exec /usr/bin/websockify --web=/usr/share/novnc 0.0.0.0:6080 localhost:5900
""".format(home=account.pw_dir, password_file=password_file), encoding="utf-8")
os.chown(launcher, account.pw_uid, account.pw_gid)
os.chmod(launcher, 0o700)

browser_launcher = desktop_dir / "launch-browser.py"
browser_launcher.write_text("""import os
import subprocess

environment = os.environ.copy()
environment.update({{
    "HOME": {home!r},
    "DISPLAY": ":99",
    "XDG_RUNTIME_DIR": "/run/user/{uid}",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/{uid}/bus",
}})
subprocess.Popen(
    ["firefox", "--no-remote", "about:debugging#/runtime/this-firefox"],
    env=environment,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
""".format(home=account.pw_dir, uid=account.pw_uid), encoding="utf-8")
os.chown(browser_launcher, account.pw_uid, account.pw_gid)
os.chmod(browser_launcher, 0o700)

unit = pathlib.Path("/etc/systemd/system/atomic-desktop.service")
unit.write_text("""[Unit]
Description=Atomic Red Team disposable browser desktop
After=network-online.target snapd.service
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={group}
Environment=HOME={home}
Environment=XDG_RUNTIME_DIR=/run/atomic-desktop
RuntimeDirectory=atomic-desktop
ExecStart=/usr/bin/dbus-run-session -- {launcher}
ExecStopPost=-/usr/bin/pkill -u {uid} -f firefox
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""".format(user=execution_user, group=group_name, home=account.pw_dir, launcher=launcher, uid=account.pw_uid), encoding="utf-8")
os.chmod(unit, 0o644)
subprocess.run(["loginctl", "enable-linger", execution_user], check=True)
subprocess.run(["systemctl", "start", "user@{}.service".format(account.pw_uid)], check=True)
subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(["systemctl", "enable", "--now", "atomic-desktop.service"], check=True)
`;

export type DesktopAccess = {
  readonly url: string;
  readonly password_command: string;
  readonly service: string;
  readonly display: string;
};

export async function installDesktopProfile(
  scope: AtomicPlan["scope"],
  runId: string
): Promise<{
  readonly ok: boolean;
  readonly install: Awaited<ReturnType<typeof runOnTarget>>;
  readonly status: Awaited<ReturnType<typeof runOnTarget>>;
  readonly browser_launch?: Awaited<ReturnType<typeof runOnTarget>>;
  readonly browser?: Awaited<ReturnType<typeof runOnTarget>>;
  readonly vnc?: Awaited<ReturnType<typeof runOnTarget>>;
  readonly access?: DesktopAccess;
}> {
  const install = await runOnTarget(
    scope,
    ["sudo", "python3", "-", scope.execution_user, runId],
    2 * 60_000,
    { input: DESKTOP_INSTALLER_SOURCE }
  );
  const status = await runOnTarget(
    scope,
    ["sudo", "systemctl", "is-active", DESKTOP_SERVICE],
    30_000
  );
  const browserLauncher = `/var/tmp/atomic-runs/${runId}/desktop/launch-browser.py`;
  const browserLaunch = await runOnTarget(
    scope,
    ["sudo", "-u", scope.execution_user, "--", "python3", browserLauncher],
    30_000
  );
  if (browserLaunch.exitCode === 0 && !browserLaunch.timedOut) {
    await runOnTarget(scope, ["sleep", "8"], 15_000);
  }
  const [browser, vnc] = await Promise.all([
    runOnTarget(
      scope,
      ["sudo", "pgrep", "-u", scope.execution_user, "-f", "firefox"],
      30_000
    ),
    runOnTarget(
      scope,
      ["sudo", "pgrep", "-u", scope.execution_user, "-x", "x11vnc"],
      30_000
    ),
  ]);
  if (
    install.exitCode !== 0 ||
    install.timedOut ||
    browserLaunch.exitCode !== 0 ||
    browserLaunch.timedOut ||
    status.exitCode !== 0 ||
    status.stdout.trim() !== "active" ||
    browser.exitCode !== 0 ||
    browser.timedOut ||
    vnc.exitCode !== 0 ||
    vnc.timedOut
  ) {
    return { ok: false, install, status, browser_launch: browserLaunch, browser, vnc };
  }
  const addresses = await runOnTarget(scope, ["hostname", "-I"], 30_000);
  const address = addresses.stdout
    .trim()
    .split(/\s+/)
    .find((candidate) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(candidate));
  if (addresses.exitCode !== 0 || !address) {
    return {
      ok: false,
      install,
      status: addresses,
      browser_launch: browserLaunch,
      browser,
      vnc,
    };
  }
  const passwordPath = `/var/tmp/atomic-runs/${runId}/desktop/vnc-password`;
  return {
    ok: true,
    install,
    status,
    browser_launch: browserLaunch,
    browser,
    vnc,
    access: {
      url: `http://${address}:6080/vnc.html?autoconnect=1&resize=scale`,
      password_command: `multipass exec ${scope.target_id} -- sudo cat ${passwordPath}`,
      service: DESKTOP_SERVICE,
      display: ":99",
    },
  };
}
