
import os, zipfile

def export_case(case_dir, fmt):
    base = os.path.abspath(case_dir.rstrip("/\\"))
    case_id = os.path.basename(base)
    out = base + ".zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(base):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, base)
                z.write(full, arcname=os.path.join(case_id, rel))
    
    # PGP sign the zip file if keys available
    if os.environ.get("PAW_PGP_PRIV"):
        try:
            from .signature import sign_file_pgp
            sig_path = out + ".asc"
            sign_file_pgp(out, os.environ["PAW_PGP_PRIV"], os.environ.get("PAW_PGP_PASS"), sig_path)
            print(f"[pgp] export signed: {sig_path}")
        except Exception as e:
            print(f"[pgp] signing failed: {e}")
    
    print(out)
    return out
