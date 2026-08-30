import subprocess,sys
def test_clean_subprocess_imports_restricted_modules_without_hermes_runtime():
    code="import sys; import restricted_runtime.contracts, restricted_runtime.conversation, restricted_runtime.gateway; assert not any(x.startswith(('agent','run_agent','plugins','tools')) for x in sys.modules)"
    assert subprocess.run([sys.executable,"-c",code],capture_output=True,text=True).returncode==0
