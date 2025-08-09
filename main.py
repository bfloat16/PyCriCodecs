import argparse
from tqdm import tqdm
from pathlib import Path
from PyCriCodecs.acb import ACB
from PyCriCodecs.awb import AWB

def extract_one(acb_path: Path, out_root: Path):
    acb = ACB(str(acb_path))

    embedded_awb_bytes = None
    try:
        payload = getattr(acb, "_payload", None)
        if payload and len(payload) >= 1:
            awb_field = payload[0].get("AwbFile")
            if isinstance(awb_field, (list, tuple)) and len(awb_field) >= 2:
                if isinstance(awb_field[1], (bytes, bytearray)) and len(awb_field[1]) > 0:
                    embedded_awb_bytes = awb_field[1]
    except Exception as e:
        pass

    if embedded_awb_bytes:
        awb = AWB(embedded_awb_bytes)
    else:
        external_awb = acb_path.with_suffix(".awb")
        if 'vo_adv_0000011' in external_awb.name:
            pass
        if not external_awb.exists():
            return  
        awb = AWB(str(external_awb))

    out_dir = out_root / acb_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)

    a = acb.extract()
    AWB.extract(awb, a, str(out_dir))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", default=r"D:\Dataset_Game\jp.co.cygames.princessconnectredive\RAW\v")
    parser.add_argument("--out", default=r"D:\Dataset_Game\jp.co.cygames.princessconnectredive\EXP\v")
    args = parser.parse_args()

    root = Path(args.folder)
    out_root = Path(args.out)
    if not root.exists():
        raise FileNotFoundError(f"输入目录不存在：{root}")

    acb_files = list(root.rglob("*.acb"))

    for acb_path in tqdm(acb_files, ncols=150):
        extract_one(acb_path, out_root)