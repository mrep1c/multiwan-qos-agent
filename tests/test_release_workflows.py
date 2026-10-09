"""Exercise shipped release scripts with Git and GitHub operations mocked."""
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PWSH = shutil.which("pwsh") or shutil.which("powershell.exe")
PUSH_SHA = "b" * 40
BUMP_SHA = "c" * 40


def workflow_script(filename, step):
    text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
    section = text.split("      - name: " + step, 1)[1].split("        run: |\n", 1)[1]
    lines = []
    for line in section.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


@unittest.skipUnless(PWSH, "PowerShell required for workflow script checks")
class ReleaseWorkflowTests(unittest.TestCase):
    def run_script(self, filename, step, changed=(), fail_push=False, fail_publish=False, manual=False):
        with tempfile.TemporaryDirectory(prefix="release-test-", dir=ROOT) as name:
            directory = Path(name).resolve()
            self.assertTrue(directory.is_relative_to(ROOT))
            package = directory / "multiwan_qos_agent"
            package.mkdir()
            version_file = package / "__init__.py"
            version_file.write_text('__version__ = "1.0.11"\n', encoding="utf-8")
            output, calls = directory / "output", directory / "calls"
            output.touch()
            calls.touch()
            changes = directory / "changes.json"
            changes.write_text(json.dumps(list(changed)), encoding="utf-8")
            script = workflow_script(filename, step)
            for expression, value in {
                "github.event.before": "a" * 40, "github.sha": PUSH_SHA,
                "steps.asset.outputs.version": "1.0.11",
                "steps.asset.outputs.asset_name": "MultiWAN-QoS-Agent-v1.0.11-windows-x64.exe",
                "steps.asset.outputs.asset_path": "dist/agent.exe",
            }.items():
                script = script.replace("${{ " + expression + " }}", value)
            self.assertNotIn("${{", script)
            mocks = r'''
$ErrorActionPreference = 'Stop'
function git {
    Add-Content -LiteralPath $env:RELEASE_CALLS ("git " + ($args -join " "))
    $global:LASTEXITCODE = 0
    switch ($args[0]) {
        'diff' { Get-Content -Raw -LiteralPath $env:RELEASE_CHANGES | ConvertFrom-Json }
        'status' { ' M multiwan_qos_agent/__init__.py' }
        'rev-parse' { $env:RELEASE_BUMP_SHA }
        'push' { if ($env:RELEASE_FAIL_PUSH -eq '1') { $global:LASTEXITCODE = 1 } }
        { $_ -in 'config', 'add', 'commit' } { }
        default { throw "Unexpected Git operation: $args" }
    }
}
function gh {
    Add-Content -LiteralPath $env:RELEASE_CALLS ("gh " + ($args -join " "))
    $global:LASTEXITCODE = 0
    switch ($args[1]) {
        'view' { $global:LASTEXITCODE = 1 }
        'create' { if ($env:RELEASE_FAIL_PUBLISH -eq '1') { $global:LASTEXITCODE = 1 } }
        default { throw "Unexpected GitHub operation: $args" }
    }
}
'''
            script_file = directory / "workflow.ps1"
            script_file.write_text(mocks + "\n" + script, encoding="utf-8")
            env = {**os.environ, "GITHUB_OUTPUT": str(output), "RELEASE_CALLS": str(calls),
                   "GITHUB_EVENT_NAME": "workflow_dispatch" if manual else "push",
                   "RELEASE_CHANGES": str(changes), "RELEASE_BUMP_SHA": BUMP_SHA,
                   "RELEASE_FAIL_PUSH": str(int(fail_push)), "RELEASE_FAIL_PUBLISH": str(int(fail_publish))}
            result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script_file)],
                                    cwd=directory, env=env, capture_output=True, text=True, timeout=30)
            return result, output.read_text(encoding="utf-8-sig"), calls.read_text(encoding="utf-8-sig"), version_file.read_text(encoding="utf-8-sig")

    def bump(self, **kwargs):
        return self.run_script("auto-bump-version.yml", "Bump Windows agent version when app changes", **kwargs)

    def test_app_push_releases_the_successfully_pushed_bump(self):
        result, output, calls, version = self.bump(changed=["multiwan_qos_agent/app.py"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('__version__ = "1.0.12"', version)
        self.assertIn("git push", calls)
        self.assertIn("release_ref=" + BUMP_SHA, output)

    def test_explicit_version_push_releases_without_another_bump(self):
        result, output, calls, version = self.bump(changed=["multiwan_qos_agent/__init__.py"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release_ref=" + PUSH_SHA, output)
        self.assertNotIn("git push", calls)
        self.assertIn('"1.0.11"', version)

    def test_documentation_push_does_not_publish(self):
        result, output, calls, _ = self.bump(changed=["README.md"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "")
        self.assertNotIn("git push", calls)

    def test_manual_publish_uses_current_version_without_bumping(self):
        result, output, calls, version = self.bump(manual=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release_ref=" + PUSH_SHA, output)
        self.assertEqual(calls, "")
        self.assertIn('"1.0.11"', version)

    def test_failed_bump_push_does_not_schedule_a_release(self):
        result, output, _, _ = self.bump(changed=["multiwan_qos_agent/app.py"], fail_push=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_published_tag_targets_the_built_commit(self):
        result, _, calls, _ = self.run_script("build-windows.yml", "Publish GitHub release asset")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("gh release create v1.0.11 dist/agent.exe --target " + BUMP_SHA, calls)

    def test_publishing_failure_fails_the_workflow(self):
        result, _, _, _ = self.run_script("build-windows.yml", "Publish GitHub release asset", fail_publish=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
