#!/usr/bin/env python3
"""Run the bounded local single-node evaluation journey with real product binaries."""
from __future__ import annotations
import argparse, hashlib, json, os, secrets, shutil, signal, socket, subprocess, sys, time, urllib.request
from pathlib import Path


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""): h.update(chunk)
    return h.hexdigest()

def write(path: Path, data: bytes) -> None:
    path.write_bytes(data); path.chmod(0o600)

def run(command:list[str], env:dict[str,str], cwd:Path|None=None, accepted=(0,)) -> subprocess.CompletedProcess[bytes]:
    result=subprocess.run(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
    if result.returncode not in accepted:
        raise RuntimeError(f"command failed ({result.returncode}): {command[0]} {command[1:]}\n{result.stderr.decode('utf-8','replace')}")
    return result

def free_port() -> int:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0); sock.bind(("127.0.0.1",0)); return int(sock.getsockname()[1])

def request(url:str, token:str|None=None) -> bytes:
    headers={"Accept":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url,headers=headers),timeout=5) as response:
        if response.status!=200: raise RuntimeError(f"HTTP {response.status}: {url}")
        return response.read()

def start_daemon(binary:Path,args:list[str],env:dict[str,str],log:Path,url:str) -> subprocess.Popen[bytes]:
    stream=log.open("wb")
    process=subprocess.Popen([str(binary),*args],env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
    process._trestle_log=stream  # type: ignore[attr-defined]
    try:
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if process.poll() is not None: raise RuntimeError(f"trestled exited {process.returncode}: {log.read_text(errors='replace')}")
            try:
                request(url+"/readyz"); return process
            except Exception: time.sleep(0.1)
        raise RuntimeError("trestled readiness timeout")
    except Exception:
        stop_daemon(process)
        raise

def stop_daemon(process:subprocess.Popen[bytes]|None) -> None:
    if process is None: return
    if process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        try: process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL); process.wait(timeout=5)
    stream=getattr(process,"_trestle_log",None)
    if stream: stream.close()

def canonical_json(value:object)->bytes:
    return json.dumps(value,separators=(",",":"),sort_keys=True).encode()

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--candidate",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--source-root",type=Path,default=Path.cwd())
    parser.add_argument("--browser-script",type=Path,required=True)
    args=parser.parse_args()
    candidate=args.candidate.resolve(); output=args.output.resolve(); source=args.source_root.resolve(); browser_script=args.browser_script.resolve()
    sidecar=Path(str(candidate)+".sha256")
    if not candidate.is_file() or not sidecar.is_file() or not browser_script.is_file() or output.exists(): raise SystemExit("candidate, checksum, and browser script must exist and output must not exist")
    sidecar_fields=sidecar.read_text().strip().split()
    if len(sidecar_fields)<1 or sidecar_fields[0]!=sha256(candidate): raise SystemExit("candidate checksum does not match detached sidecar")
    source_revision=subprocess.run(["git","rev-parse","HEAD"],cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,text=True).stdout.strip()
    source_tree_identity=subprocess.run(["git","rev-parse","HEAD^{tree}"],cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,text=True).stdout.strip()
    source_status=subprocess.run(["git","status","--porcelain=v1","--untracked-files=all"],cwd=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,text=True).stdout
    if source_status: raise SystemExit("source tree must be clean before system verification")
    output.mkdir(mode=0o700,parents=True)
    home=output/"home"; runtime=output/"runtime"; setup_dir=output/"setup"; repo=output/"repository"; artifacts=output/"artifacts"
    for directory in (home,runtime,setup_dir,repo,artifacts): directory.mkdir(mode=0o700)
    token=secrets.token_hex(32)
    env={"HOME":str(home),"PATH":os.environ.get("PATH","/usr/bin:/bin"),"OPEN_TRESTLE_API_TOKEN":token,"HTTP_PROXY":"http://127.0.0.1:9","HTTPS_PROXY":"http://127.0.0.1:9","ALL_PROXY":"http://127.0.0.1:9","NO_PROXY":"127.0.0.1,::1","GOTELEMETRY":"off"}
    commands:list[list[str]]=[]
    def execute(command:list[str],cwd:Path|None=None,accepted=(0,)):
        commands.append(command); return run(command,env,cwd,accepted)
    candidate_root=output/"candidate-root"; candidate_root.mkdir(mode=0o700)
    for sentinel in (candidate_root/"etc/open-trestle/operator.conf",candidate_root/"var/lib/open-trestle/operator.state"):
        sentinel.parent.mkdir(mode=0o700,parents=True); write(sentinel,b"operator-owned\n")
    verify_archive=execute([str(candidate),"verify-archive"]); write(artifacts/"candidate-verify-archive.json",verify_archive.stdout)
    installed=execute([str(candidate),"install","--destdir",str(candidate_root)]); write(artifacts/"candidate-install.json",installed.stdout)
    lifecycle=candidate_root/"usr/local/libexec/open-trestle/open-trestle-distribution.pyz"
    verified=execute([str(lifecycle),"verify-installed","--destdir",str(candidate_root)]); write(artifacts/"candidate-verify-installed.json",verified.stdout)
    execute([str(lifecycle),"smoke","--destdir",str(candidate_root),"--output",str(artifacts/"candidate-smoke.json")])
    trestle=candidate_root/"usr/local/bin/trestle"; trestled=candidate_root/"usr/local/bin/trestled"
    if not trestle.is_file() or not trestled.is_file(): raise RuntimeError("candidate did not install product binaries")
    execute(["git","init","--object-format=sha1",str(repo)])
    execute(["git","config","user.name","Open Trestle evaluator"],repo); execute(["git","config","user.email","evaluator@example.invalid"],repo)
    (repo/"main.go").write_text('package main\n\nfunc main() {}\n'); execute(["git","add","main.go"],repo); execute(["git","commit","-m","base"],repo)
    base=execute(["git","rev-parse","HEAD"],repo).stdout.decode().strip()
    (repo/"main.go").write_text('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("debug") }\n'); execute(["git","add","main.go"],repo); execute(["git","commit","-m","head"],repo)
    head=execute(["git","rev-parse","HEAD"],repo).stdout.decode().strip(); objects=(repo/".git"/"objects").resolve()
    setup_path=setup_dir/"plan.json"
    setup=execute([str(trestle),"setup","init","--profile","local_single_node","--tenant","tenant-a","--repository","repository-a","--recovery-owner","platform-owner","--state",str(setup_path)])
    write(artifacts/"setup-init.json",setup.stdout); setup_root=json.loads(setup.stdout)["plan_identity"]
    inspect=execute([str(trestle),"setup","inspect","--state",str(setup_path),"--expected-root-identity",setup_root]); write(artifacts/"setup-plan.json",inspect.stdout)
    inspected_setup=json.loads(inspect.stdout)
    if inspected_setup["ready"] is not False or inspected_setup["status"]!="incomplete": raise RuntimeError("deterministic alpha must not imply setup readiness")
    port=free_port(); url=f"http://127.0.0.1:{port}"
    daemon_args=["--listen",f"127.0.0.1:{port}","--state-dir",str(runtime),"--tenant","tenant-a","--repository","repository-a","--setup-state",str(setup_path),"--expected-setup-root-identity",setup_root,"--local-git-objects-root",str(objects),"--local-git-repository-authority","local.test","--local-git-repository-namespace","team","--local-git-repository-name","repository"]
    daemon=None
    try:
        daemon=start_daemon(trestled,daemon_args,env,artifacts/"trestled-first.log",url)
        submit_args=[str(trestle),"local-git","review","--objects-root",str(objects),"--repository-authority","local.test","--repository-namespace","team","--repository-name","repository","--revision-algorithm","sha1","--base-revision-digest",base,"--head-revision-digest",head,"--tenant","tenant-a","--repository","repository-a","--run","local-alpha","--server",url]
        submitted=execute(submit_args); write(artifacts/"submission.json",submitted.stdout); run_id=json.loads(submitted.stdout)["review_run_id"]
        status_args=[str(trestle),"runs","status","--tenant","tenant-a","--repository","repository-a","--run",run_id,"--server",url]
        deadline=time.monotonic()+20
        while True:
            status=execute(status_args); status_value=json.loads(status.stdout)
            if status_value["status"]!="active": break
            if time.monotonic()>=deadline: raise RuntimeError("review did not become terminal")
            time.sleep(1)
        if status_value["status"]!="succeeded" or len(status_value["tasks"])!=4: raise RuntimeError("review did not succeed through four durable tasks")
        write(artifacts/"status-before-restart.json",status.stdout)
        diagnostics=request(url+f"/api/v1/tenants/tenant-a/repositories/repository-a/runs/{run_id}/diagnostics",token); write(artifacts/"diagnostics-before-restart.json",diagnostics)
        console=request(url+"/console/"); write(artifacts/"console.html",console)
        tui=execute([str(trestle),"tui","--server",url,"--tenant","tenant-a","--repository","repository-a","--run",run_id,"--plain","--once"]); write(artifacts/"tui-before-restart.txt",tui.stdout)
        json_first=execute([*status_args,"--format","json"]); sarif_first=execute([*status_args,"--format","sarif"]); write(artifacts/"result.json",json_first.stdout); write(artifacts/"result.sarif.json",sarif_first.stdout)
        if json.loads(json_first.stdout)["schema_version"]!=6 or len(json.loads(sarif_first.stdout)["runs"][0]["results"])!=1: raise RuntimeError("deterministic exports are incomplete")
        stop_daemon(daemon); daemon=None
        daemon=start_daemon(trestled,daemon_args,env,artifacts/"trestled-restart.log",url)
        status_after=execute(status_args); diagnostics_after=request(url+f"/api/v1/tenants/tenant-a/repositories/repository-a/runs/{run_id}/diagnostics",token)
        json_after=execute([*status_args,"--format","json"]); sarif_after=execute([*status_args,"--format","sarif"])
        write(artifacts/"status-after-restart.json",status_after.stdout); write(artifacts/"diagnostics-after-restart.json",diagnostics_after); write(artifacts/"tui-after-restart.txt",execute([str(trestle),"tui","--server",url,"--tenant","tenant-a","--repository","repository-a","--run",run_id,"--plain","--once"]).stdout)
        visual_env={**env,"OPEN_TRESTLE_DAEMON_URL":url,"OPEN_TRESTLE_DAEMON_VISUAL_OUTPUT":str(artifacts/"daemon-console"),"OPEN_TRESTLE_TENANT":"tenant-a","OPEN_TRESTLE_REPOSITORY":"repository-a","OPEN_TRESTLE_RUN":run_id}
        commands.append(["node",str(browser_script)]); visual=run(["node",str(browser_script)],visual_env,source); write(artifacts/"daemon-console-visual.stdout",visual.stdout); write(artifacts/"daemon-console-visual.stderr",visual.stderr)
        if json.loads(status_after.stdout)["identity"]!=status_value["identity"] or json.loads(diagnostics_after)["diagnostics"]!=json.loads(diagnostics)["diagnostics"] or json_after.stdout!=json_first.stdout or sarif_after.stdout!=sarif_first.stdout: raise RuntimeError("restart or deterministic readback mismatch")
    finally: stop_daemon(daemon)
    binary_records=[{"name":"trestle","path":str(trestle),"sha256":sha256(trestle)},{"name":"trestled","path":str(trestled),"sha256":sha256(trestled)}]
    uninstalled=execute([str(lifecycle),"uninstall","--destdir",str(candidate_root)]); write(artifacts/"candidate-uninstall.json",uninstalled.stdout)
    if trestle.exists() or trestled.exists() or not (candidate_root/"etc/open-trestle/operator.conf").is_file() or not (candidate_root/"var/lib/open-trestle/operator.state").is_file(): raise RuntimeError("candidate uninstall did not preserve operator state or remove binaries")
    revision=source_revision
    artifact_records=[]
    for path in sorted(artifacts.rglob("*")):
        if path.is_file(): artifact_records.append({"name":str(path.relative_to(artifacts)),"sha256":sha256(path),"bytes":path.stat().st_size})
    receipt={"contract":"open-trestle/local-alpha-system-receipt","schema_version":1,"source_revision":revision,"source_tree_identity":source_tree_identity,"source_tree_clean":True,"candidate":{"path":str(candidate),"sha256":sha256(candidate),"sidecar_sha256":sha256(sidecar),"lifecycle":"verified_install_smoke_uninstall","operator_state_preserved":True},"binaries":binary_records,"repository":{"base_revision":base,"head_revision":head},"review":{"tenant_id":"tenant-a","repository_id":"repository-a","review_run_id":"local-alpha","run_receipt_identity":status_value["identity"],"diagnostic_set_identity":json.loads(diagnostics)["diagnostics"]["identity"]},"commands":commands,"artifacts":artifact_records,"restart":{"status_identity_stable":True,"diagnostics_bytes_stable":True,"json_bytes_stable":True,"sarif_bytes_stable":True},"setup":{"profile":"local_single_node","plan_identity":setup_root,"ready":False,"authority":"scope_and_denied_effect_posture_only"},"network":{"daemon":"numeric_loopback_only","proxies":"disabled_for_loopback_and_forced_closed_elsewhere"},"cleanup":{"daemon_stopped":True,"candidate_uninstalled":True,"operator_state_preserved":True,"host_modified":False}}
    write(output/"receipt.json",canonical_json(receipt)+b"\n")
    return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as exc: print(f"local alpha system verification failed: {exc}",file=sys.stderr); raise SystemExit(1)
