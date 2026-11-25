#!/usr/bin/env python3
"""
reforge - أداة هندسة عكسية موحدة لاسترجاع تطبيقاتك أنت (Recovery of your OWN apps).

الأوامر:
  reforge analyze <target> -o out/   تحليل كامل: فك الحزمة، معمارية، نماذج AI، تقرير + spec
  reforge models  <path>             فحص ملفات النماذج فقط (gguf/safetensors/onnx/tflite/pt)
  reforge doctor                     يعرض الأدوات الخارجية المتاحة (jadx, apktool, ...)

يعتمد على مكتبة بايثون القياسية فقط. الأدوات الخارجية اختيارية ويتم استدعاؤها لو موجودة.
مخصص لتطبيقات تملكها أو لديك تصريح بتحليلها. لا يحتوي على كسر تشفير أو حماية.
"""
import argparse
import hashlib
import json
import math
import marshal
import mmap
import os
import pickletools
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"

# ----------------------------------------------------------------------------
# أدوات مساعدة
# ----------------------------------------------------------------------------

EXTERNAL_TOOLS = {
    "apktool": "فك موارد APK والمانيفست (smali)",
    "jadx": "تحويل dex إلى Java/Kotlin قابل للقراءة",
    "ilspycmd": "تفكيك تطبيقات .NET إلى C#",
    "pycdc": "فك pyc إلى Python (يدعم إصدارات حديثة جزئيا)",
    "decompyle3": "فك pyc لبايثون 3.7-3.8",
    "uncompyle6": "فك pyc لبايثون حتى 3.8",
    "ghidraRun": "Ghidra للتحليل الثنائي الأصلي",
    "strings": "استخراج النصوص من الثنائيات",
}


def sha256(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.1f}{u}" if u != "B" else f"{n}B"
        n /= 1024


def safe_join(base: Path, name: str) -> Path:
    name = name.replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    return base.joinpath(*parts)


def unzip(path, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            target = safe_join(dest, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            n += 1
    return n


def run_tool(name, args, log: Path, timeout=1800):
    exe = shutil.which(name)
    if not exe:
        return None
    try:
        with open(log, "wb") as lf:
            r = subprocess.run([exe, *args], stdout=lf, stderr=subprocess.STDOUT, timeout=timeout)
        return r.returncode
    except Exception as e:  # noqa
        log.write_text(f"failed: {e}")
        return -1


# ----------------------------------------------------------------------------
# Android binary manifest (AXML)
# ----------------------------------------------------------------------------

def parse_axml(data: bytes):
    u16 = lambda o: struct.unpack_from("<H", data, o)[0]
    u32 = lambda o: struct.unpack_from("<I", data, o)[0]
    if u16(0) != 0x0003:
        raise ValueError("not AXML")
    total = min(u32(4), len(data))
    pos, strings, elems = 8, [], []
    while pos + 8 <= total:
        ctype, hsize, size = u16(pos), u16(pos + 2), u32(pos + 4)
        if size < 8:
            break
        if ctype == 0x0001:
            scount, flags, sstart = u32(pos + 8), u32(pos + 16), u32(pos + 20)
            utf8 = bool(flags & 0x100)
            for i in range(scount):
                p = pos + sstart + u32(pos + hsize + 4 * i)
                if utf8:
                    if data[p] & 0x80:
                        p += 1
                    p += 1
                    ln = data[p]
                    p += 1
                    if ln & 0x80:
                        ln = ((ln & 0x7F) << 8) | data[p]
                        p += 1
                    strings.append(data[p:p + ln].decode("utf8", "replace"))
                else:
                    ln = u16(p)
                    p += 2
                    if ln & 0x8000:
                        ln = ((ln & 0x7FFF) << 16) | u16(p)
                        p += 2
                    strings.append(data[p:p + ln * 2].decode("utf-16le", "replace"))
        elif ctype == 0x0102:
            name = u32(pos + 20)
            astart, acount = u16(pos + 24), u16(pos + 28)
            attrs = {}
            for i in range(acount):
                a = pos + 16 + astart + 20 * i
                an, raw, vtype, vdata = u32(a + 4), u32(a + 8), data[a + 15], u32(a + 16)
                key = strings[an] if an < len(strings) else str(an)
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                elif vtype == 0x12:
                    val = bool(vdata)
                else:
                    val = vdata
                attrs[key] = val
            elems.append((strings[name] if name < len(strings) else "?", attrs))
        pos += size
    return elems


def android_manifest_summary(elems):
    out = {"package": None, "version_name": None, "version_code": None, "min_sdk": None,
           "target_sdk": None, "permissions": [], "activities": [], "services": [],
           "receivers": [], "providers": [], "features": [], "application": {}}
    for tag, a in elems:
        if tag == "manifest":
            out["package"] = a.get("package")
            out["version_name"] = a.get("versionName")
            out["version_code"] = a.get("versionCode")
        elif tag == "uses-sdk":
            out["min_sdk"], out["target_sdk"] = a.get("minSdkVersion"), a.get("targetSdkVersion")
        elif tag == "uses-permission":
            out["permissions"].append(a.get("name"))
        elif tag == "uses-feature":
            out["features"].append(a.get("name"))
        elif tag in ("activity", "service", "receiver", "provider"):
            out[{"activity": "activities", "service": "services",
                 "receiver": "receivers", "provider": "providers"}[tag]].append(a.get("name"))
        elif tag == "application":
            out["application"] = {k: v for k, v in a.items() if k in ("name", "label", "debuggable", "allowBackup", "usesCleartextTraffic")}
    return out


# ----------------------------------------------------------------------------
# PE / بصمات التقنيات
# ----------------------------------------------------------------------------

def pe_info(path):
    with open(path, "rb") as f:
        d = f.read(64)
        if d[:2] != b"MZ":
            return None
        off = struct.unpack_from("<I", d, 0x3C)[0]
        f.seek(off)
        h = f.read(264 + 40 * 16)
    if h[:4] != b"PE\0\0":
        return None
    machine, nsec, ts, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", h, 4)
    magic = struct.unpack_from("<H", h, 24)[0]
    dd = 24 + (112 if magic == 0x20B else 96)
    clr_rva = struct.unpack_from("<I", h, dd + 14 * 8)[0] if len(h) >= dd + 120 else 0
    secs = []
    so = 24 + optsize
    for i in range(min(nsec, 16)):
        if so + 40 * (i + 1) <= len(h):
            secs.append(h[so + 40 * i: so + 40 * i + 8].rstrip(b"\0").decode("latin1"))
    return {"machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, hex(machine)),
            "pe32plus": magic == 0x20B, "timestamp": ts, "sections": secs,
            "is_dll": bool(chars & 0x2000), "dotnet": clr_rva != 0}


BIN_SIGNATURES = [
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller"),
    (b"Inno Setup Setup Data", "Inno Setup installer"),
    (b"Nullsoft Install System", "NSIS installer"),
    (b"Go build ID", "Go"),
    (b"rustc version", "Rust"),
    (b"This is a Nuitka", "Nuitka"),
    (b"Py_Initialize", "embeds CPython"),
    (b"app.asar", "Electron"),
    (b"BSJB", ".NET metadata"),
    (b"Qt6Core", "Qt6"),
    (b"Qt5Core", "Qt5"),
    (b"onnxruntime", "ONNX Runtime"),
    (b"tensorflow", "TensorFlow"),
    (b"libtorch", "PyTorch (libtorch)"),
    (b"llama.cpp", "llama.cpp"),
]

APK_LIBS = {
    "libflutter.so": "Flutter", "libapp.so": "Flutter (Dart AOT)",
    "libreactnativejni.so": "React Native", "libhermes.so": "React Native (Hermes)",
    "libunity.so": "Unity", "libil2cpp.so": "Unity IL2CPP", "libmonodroid.so": "Xamarin/.NET",
    "libgodot_android.so": "Godot", "libtensorflowlite_jni.so": "TensorFlow Lite",
    "libonnxruntime.so": "ONNX Runtime", "libpytorch_jni.so": "PyTorch Mobile",
    "libtorch_android.so": "PyTorch Mobile", "libmnn.so": "MNN", "libncnn.so": "ncnn",
    "libllama.so": "llama.cpp", "libchaquopy_java.so": "Chaquopy (Python)",
}


def scan_signatures(path, limit=400 << 20):
    found = []
    size = os.path.getsize(path)
    if size == 0 or size > limit:
        return found
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for sig, label in BIN_SIGNATURES:
            if m.find(sig) != -1:
                found.append(label)
    return found


SECRET_PATTERNS = {
    "Anthropic key": re.compile(rb"sk-ant-[A-Za-z0-9\-_]{20,}"),
    "OpenAI-style key": re.compile(rb"sk-[A-Za-z0-9]{32,}"),
    "Google API key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Private key block": re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}
URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")


def mask(s: str):
    return s[:6] + "…" + s[-3:] if len(s) > 12 else "***"


def scan_text_artifacts(root: Path, max_files=3000, max_size=60 << 20):
    urls, secrets = Counter(), []
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        n += 1
        if n > max_files:
            break
        try:
            if p.stat().st_size > max_size:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        for m in URL_RE.findall(data):
            u = m.decode("latin1")
            if not re.search(r"(w3\.org|schemas\.android|apache\.org|xmlpull|example\.com|googleapis\.com/auth)", u):
                urls[u] += 1
        for label, rx in SECRET_PATTERNS.items():
            for m in rx.findall(data):
                secrets.append({"type": label, "file": str(p.relative_to(root)), "masked": mask(m.decode("latin1"))})
    return urls, secrets


# ----------------------------------------------------------------------------
# PyInstaller
# ----------------------------------------------------------------------------

PYC_MAGIC = {(3, 8): 3413, (3, 9): 3425, (3, 10): 3439, (3, 11): 3495, (3, 12): 3531, (3, 13): 3571}
THIRD_PARTY_HINT = {"PyQt6", "PyQt5", "PySide6", "PySide2", "numpy", "anthropic", "google", "httpx", "httpcore",
                    "pydantic", "pydantic_core", "requests", "urllib3", "certifi", "charset_normalizer", "idna",
                    "anyio", "sniffio", "h11", "typing_extensions", "yaml", "cryptography", "cffi", "pycparser",
                    "PIL", "pandas", "scipy", "psutil", "win32com", "win32api", "pywin32", "pkg_resources",
                    "setuptools", "_distutils_hack", "jaraco", "six", "dateutil", "pytz", "tqdm", "rich", "pygments",
                    "markdown_it", "mdurl", "distro", "jiter", "tokenizers", "websockets", "grpc", "proto", "rsa",
                    "pyasn1", "pyasn1_modules", "cachetools", "tzdata", "attr", "attrs", "orjson", "onnxruntime"}


def pyinstaller_extract(path: Path, out: Path):
    size = path.stat().st_size
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        cpos = m.rfind(b"MEI\x0c\x0b\x0a\x0b\x0e")
        if cpos < 0:
            return None
        magic, pkglen, toc, toclen, pyver = struct.unpack_from("!8sIIII", m, cpos)
        csize = 88 if b"python" in bytes(m[cpos + 24: cpos + 88]).lower() else 24
        tail = size - cpos - csize
        overlay = size - (pkglen + tail)
        pos = overlay + toc
        end = pos + toclen
        entries = []
        while pos < end:
            esz = struct.unpack_from("!I", m, pos)[0]
            epos, clen, ulen, flag, typ = struct.unpack_from("!IIIBc", m, pos + 4)
            name = bytes(m[pos + 18: pos + esz]).split(b"\0")[0].decode("utf8", "replace")
            entries.append((name, epos, clen, ulen, flag, typ.decode("latin1")))
            pos += esz
        pyv = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        mg = PYC_MAGIC.get(pyv)
        header = (struct.pack("<H", mg) + b"\r\n" + b"\0" * 12) if mg else b"\0" * 16
        out.mkdir(parents=True, exist_ok=True)
        info = {"python": f"{pyv[0]}.{pyv[1]}", "entries": len(entries), "scripts": [], "app_modules": [], "toplevel": Counter()}
        for name, epos, clen, ulen, flag, typ in entries:
            raw = bytes(m[overlay + epos: overlay + epos + clen])
            if flag == 1:
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    continue
            if typ in ("s", "S"):
                tgt = safe_join(out / "scripts", name + ".pyc")
                tgt.parent.mkdir(parents=True, exist_ok=True)
                tgt.write_bytes(header + raw)
                info["scripts"].append(name)
            elif typ == "z" or name.endswith(".pyz"):
                info["toplevel"].update(_extract_pyz(raw, out / "modules", header, info))
            elif typ in ("b", "x", "d", "m", "M"):
                tgt = safe_join(out / "data", name)
                tgt.parent.mkdir(parents=True, exist_ok=True)
                tgt.write_bytes(raw)
        info["toplevel"] = dict(info["toplevel"].most_common(40))
        return info


def _extract_pyz(raw: bytes, dest: Path, header: bytes, info):
    top = Counter()
    if raw[:4] != b"PYZ\0":
        return top
    tocpos = struct.unpack_from("!I", raw, 8)[0]
    try:
        toc = marshal.loads(raw[tocpos:])
    except Exception:
        return top
    items = toc.items() if isinstance(toc, dict) else toc
    for name, (typ, pos, ln) in items:
        if isinstance(name, bytes):
            name = name.decode()
        try:
            body = zlib.decompress(raw[pos:pos + ln])
        except zlib.error:
            continue
        tl = name.split(".")[0]
        top[tl] += 1
        tgt = safe_join(dest, name.replace(".", "/") + (("/__init__" if typ in (1, 2) else "") + ".pyc"))
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_bytes(header + body)
        if tl not in THIRD_PARTY_HINT and tl not in sys.stdlib_module_names and not tl.startswith("_"):
            info["app_modules"].append(name)
    return top


def pyc_symbols(pyc: Path, cap=400):
    """يحاول قراءة الرموز (دوال/كلاسات/نصوص) لو إصدار بايثون الحالي يطابق إصدار pyc."""
    try:
        code = marshal.loads(pyc.read_bytes()[16:])
    except Exception:
        return None
    names, strs = set(), set()

    def walk(c):
        names.add(c.co_name)
        for n in c.co_names:
            names.add(n)
        for k in c.co_consts:
            if hasattr(k, "co_code"):
                walk(k)
            elif isinstance(k, str) and 3 < len(k) < 160:
                strs.add(k)
    walk(code)
    return {"names": sorted(names)[:cap], "strings": sorted(strs)[:cap]}


# ----------------------------------------------------------------------------
# Electron asar
# ----------------------------------------------------------------------------

def asar_extract(path: Path, out: Path):
    with open(path, "rb") as f:
        head = f.read(16)
        _, hdr_pickle, _, jlen = struct.unpack("<IIII", head)
        meta = json.loads(f.read(jlen))
        base = 8 + hdr_pickle
        n = 0

        def walk(node, prefix):
            nonlocal n
            for name, v in node.get("files", {}).items():
                p = f"{prefix}/{name}" if prefix else name
                if "files" in v:
                    walk(v, p)
                elif "offset" in v and not v.get("unpacked"):
                    f.seek(base + int(v["offset"]))
                    tgt = safe_join(out, p)
                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    tgt.write_bytes(f.read(int(v["size"])))
                    n += 1
        walk(meta, "")
    return n


# ----------------------------------------------------------------------------
# فحص النماذج
# ----------------------------------------------------------------------------

MODEL_EXT = {".tflite": "tflite", ".onnx": "onnx", ".safetensors": "safetensors", ".gguf": "gguf",
             ".pt": "pytorch", ".pth": "pytorch", ".ptl": "pytorch", ".ckpt": "pytorch",
             ".mlmodel": "coreml", ".h5": "keras_h5", ".hdf5": "keras_h5", ".keras": "keras",
             ".pb": "tf_pb", ".mnn": "mnn", ".param": "ncnn"}


def sniff_model(p: Path):
    try:
        size = p.stat().st_size
        with open(p, "rb") as f:
            head = f.read(65536)
    except OSError:
        return None
    ext = p.suffix.lower()
    fmt = None
    if head[:4] == b"GGUF":
        fmt = "gguf"
    elif head[4:8] == b"TFL3":
        fmt = "tflite"
    elif len(head) > 16 and head[8:9] == b"{" and struct.unpack("<Q", head[:8])[0] < min(size, 1 << 27):
        fmt = "safetensors"
    elif head[:8] == b"\x89HDF\r\n\x1a\n":
        fmt = "keras_h5"
    elif ext in (".pt", ".pth", ".ptl", ".ckpt") and head[:2] == b"PK":
        fmt = "pytorch"
    elif ext in MODEL_EXT and size > 1024:
        fmt = MODEL_EXT[ext]
    if fmt:
        return {"path": str(p), "format": fmt, "size": size}
    if size > (1 << 20) and entropy(head[:65536]) > 7.9 and ext in (".bin", ".dat", ".enc", ".model", ""):
        return {"path": str(p), "format": "opaque_high_entropy", "size": size}
    return None


def inspect_safetensors(p):
    with open(p, "rb") as f:
        n = struct.unpack("<Q", f.read(8))[0]
        hdr = json.loads(f.read(n))
    meta = hdr.pop("__metadata__", {})
    params, dts, tensors = 0, Counter(), []
    for k, v in hdr.items():
        cnt = math.prod(v["shape"]) if v["shape"] else 1
        params += cnt
        dts[v["dtype"]] += 1
        tensors.append({"name": k, "dtype": v["dtype"], "shape": v["shape"]})
    return {"tensors": len(tensors), "parameters": params, "dtypes": dict(dts), "metadata": meta, "tensor_list": tensors}


_GG = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}


def _gg_val(f, t):
    if t in _GG:
        return struct.unpack(_GG[t], f.read(struct.calcsize(_GG[t])))[0]
    if t == 8:
        n = struct.unpack("<Q", f.read(8))[0]
        return f.read(n).decode("utf8", "replace")
    if t == 9:
        et, n = struct.unpack("<IQ", f.read(12))
        vals = [_gg_val(f, et) for _ in range(n)]
        return vals if n <= 16 else f"<array of {n}>"
    raise ValueError(f"gguf type {t}")


def inspect_gguf(p):
    with open(p, "rb") as f:
        f.read(4)
        ver, tcount, kvcount = struct.unpack("<IQQ", f.read(20))
        kv = {}
        for _ in range(kvcount):
            klen = struct.unpack("<Q", f.read(8))[0]
            key = f.read(klen).decode("utf8", "replace")
            t = struct.unpack("<I", f.read(4))[0]
            kv[key] = _gg_val(f, t)
    return {"version": ver, "tensors": tcount, "architecture": kv.get("general.architecture"),
            "name": kv.get("general.name"), "metadata": {k: v for k, v in list(kv.items())[:60]}}


def inspect_onnx(p):
    try:
        import onnx  # noqa
    except ImportError:
        return {"note": "ثبّت مكتبة onnx لعرض الرسم البياني (pip install onnx)"}
    m = onnx.load(str(p), load_external_data=False)
    ops = Counter(n.op_type for n in m.graph.node)
    return {"producer": m.producer_name, "opset": [o.version for o in m.opset_import],
            "inputs": [i.name for i in m.graph.input][:20], "outputs": [o.name for o in m.graph.output],
            "initializers": len(m.graph.initializer), "ops": dict(ops.most_common(30))}


def inspect_tflite(p):
    info = {"note": "فلاتبافر TFL3. للتفاصيل: ثبّت tflite_runtime/tensorflow أو افتحه في Netron"}
    for mod in ("tflite_runtime.interpreter", "tensorflow.lite"):
        try:
            mm = __import__(mod, fromlist=["Interpreter"])
            it = mm.Interpreter(model_path=str(p))
            it.allocate_tensors()
            info = {"inputs": [{"shape": d["shape"].tolist(), "dtype": str(d["dtype"])} for d in it.get_input_details()],
                    "outputs": [{"shape": d["shape"].tolist(), "dtype": str(d["dtype"])} for d in it.get_output_details()]}
            break
        except Exception:
            continue
    return info


def inspect_pytorch(p):
    """لا يتم تنفيذ pickle أبدا؛ فقط قراءة الـ opcodes."""
    with zipfile.ZipFile(p) as z:
        names = z.namelist()
        pkl = next((n for n in names if n.endswith("data.pkl")), None)
        classes = set()
        if pkl:
            data = z.read(pkl)
            last = []
            for op, arg, _ in pickletools.genops(data):
                if op.name == "GLOBAL":
                    classes.add(str(arg).replace(" ", "."))
                elif op.name in ("SHORT_BINUNICODE", "BINUNICODE"):
                    last = (last + [arg])[-2:]
                elif op.name == "STACK_GLOBAL" and len(last) == 2:
                    classes.add(".".join(last))
    return {"archive_entries": len(names), "tensor_blobs": sum(1 for n in names if "/data/" in n),
            "referenced_classes": sorted(classes)[:60], "note": "تم الفحص بدون تنفيذ pickle"}


INSPECTORS = {"safetensors": inspect_safetensors, "gguf": inspect_gguf, "onnx": inspect_onnx,
              "tflite": inspect_tflite, "pytorch": inspect_pytorch}


def inspect_model(entry):
    fn = INSPECTORS.get(entry["format"])
    if entry["format"] == "opaque_high_entropy":
        entry["detail"] = {"note": "ملف عالي العشوائية: غالبا مشفر/مضغوط. لو تطبيقك فمفتاح التشفير موجود في كودك."}
    elif fn:
        try:
            entry["detail"] = fn(entry["path"])
        except Exception as e:  # noqa
            entry["detail"] = {"error": f"{type(e).__name__}: {e}"}
    return entry


def find_models(root: Path, cap=5000):
    out, n = [], 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        n += 1
        if n > cap:
            break
        e = sniff_model(p)
        if e:
            e["rel"] = str(p.relative_to(root)) if root.is_dir() else p.name
            out.append(e)
    return out


# ----------------------------------------------------------------------------
# التحليل الرئيسي
# ----------------------------------------------------------------------------

def detect_kind(path: Path):
    if path.is_dir():
        return "folder"
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"PK":
        try:
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
        except zipfile.BadZipFile:
            return "unknown"
        if "AndroidManifest.xml" in names:
            return "apk"
        if "base/manifest/AndroidManifest.xml" in names:
            return "aab"
        if any(n.startswith("Payload/") and ".app/" in n for n in names):
            return "ipa"
        if "META-INF/MANIFEST.MF" in names:
            return "jar"
        return "zip"
    if head[:2] == b"MZ":
        return "pe"
    if head == b"\x7fELF":
        return "elf"
    if path.suffix == ".asar":
        return "asar"
    return "unknown"


def tree_summary(root: Path):
    exts, big, total = Counter(), [], 0
    for p in root.rglob("*"):
        if p.is_file():
            s = p.stat().st_size
            total += s
            exts[p.suffix.lower() or "(none)"] += 1
            big.append((s, str(p.relative_to(root))))
    big.sort(reverse=True)
    return {"files": sum(exts.values()), "bytes": total, "by_ext": dict(exts.most_common(25)),
            "largest": [{"path": b, "size": s} for s, b in big[:15]]}


def analyze(target: Path, out: Path, external=True, copy_models=True):
    out.mkdir(parents=True, exist_ok=True)
    kind = detect_kind(target)
    facts = {"tool": f"reforge {VERSION}", "target": str(target), "kind": kind,
             "size": target.stat().st_size if target.is_file() else None,
             "sha256": sha256(target) if target.is_file() else None,
             "stack": [], "warnings": [], "external": {}, "notes": []}
    root = target
    if kind in ("apk", "aab", "ipa", "jar", "zip"):
        root = out / "unpacked"
        facts["unpacked_files"] = unzip(target, root)
    elif kind == "asar":
        root = out / "unpacked"
        facts["unpacked_files"] = asar_extract(target, root)
    elif kind == "pe":
        root = out / "unpacked"
        root.mkdir(exist_ok=True)
        facts["pe"] = pe_info(target)
        sigs = scan_signatures(target)
        facts["stack"] += sigs
        if facts["pe"] and facts["pe"]["dotnet"]:
            facts["stack"].append(".NET")
        if "PyInstaller" in sigs:
            try:
                info = pyinstaller_extract(target, out / "pyinstaller")
            except Exception as e:  # noqa
                info = None
                facts["warnings"].append(f"فشل استخراج PyInstaller: {e}")
            if info:
                facts["pyinstaller"] = info
                root = out / "pyinstaller"
        if "Electron" in sigs:
            facts["notes"].append("Electron: ابحث عن resources/app.asar بجانب الـ exe وحلله بنفس الأداة.")

    # --- تحليل حسب النوع
    if kind in ("apk", "aab"):
        mp = root / ("AndroidManifest.xml" if kind == "apk" else "base/manifest/AndroidManifest.xml")
        if mp.exists():
            try:
                facts["android"] = android_manifest_summary(parse_axml(mp.read_bytes()))
            except Exception as e:  # noqa
                facts["warnings"].append(f"تعذر قراءة المانيفست الثنائي: {e}")
        libs = {p.name for p in root.rglob("*.so")}
        facts["native_libs"] = sorted(libs)
        facts["stack"] += sorted({v for k, v in APK_LIBS.items() if k in libs})
        facts["dex_files"] = len(list(root.rglob("*.dex")))
        if (root / "assets/flutter_assets").exists():
            facts["stack"].append("Flutter")
        if list(root.rglob("index.android.bundle")):
            b = next(root.rglob("index.android.bundle"))
            facts["stack"].append("React Native (Hermes bytecode)" if b.read_bytes()[:4] == b"\x03\xbc\x1f\xc6"
                                  else "React Native (JS قابل للقراءة)")
        if list(root.rglob("global-metadata.dat")):
            facts["stack"].append("Unity IL2CPP")
        if not facts["stack"] and facts["dex_files"]:
            facts["stack"].append("Android native (Java/Kotlin)")
        if external and kind == "apk":
            facts["external"]["apktool"] = run_tool("apktool", ["d", "-f", "-o", str(out / "apktool"), str(target)], out / "apktool.log")
            facts["external"]["jadx"] = run_tool("jadx", ["-d", str(out / "jadx"), str(target)], out / "jadx.log")
    elif kind == "ipa":
        facts["stack"].append("iOS app bundle")
        facts["notes"].append("ثنائي iOS الأصلي مشفر بـ FairPlay لو نزل من المتجر؛ استخدم نسخة بنيتها بنفسك.")
    elif kind == "folder":
        if list(root.rglob("app.asar")):
            facts["stack"].append("Electron")
            a = next(root.rglob("app.asar"))
            facts["asar_files"] = asar_extract(a, out / "asar")
            root = out / "asar" if (out / "asar").exists() else root
        if list(root.rglob("*.pyc")):
            facts["stack"].append("Python bytecode")

    if kind == "pe" and (facts["pe"] or {}).get("dotnet") and external:
        facts["external"]["ilspycmd"] = run_tool("ilspycmd", ["-p", "-o", str(out / "csharp"), str(target)], out / "ilspy.log")

    # --- فك pyc (لتطبيقات بايثون)
    if "pyinstaller" in facts:
        info = facts["pyinstaller"]
        sym = {}
        targets = [out / "pyinstaller/scripts" / (s + ".pyc") for s in info["scripts"]]
        targets += [out / "pyinstaller/modules" / (m.replace(".", "/") + ".pyc") for m in info["app_modules"]]
        targets += [out / "pyinstaller/modules" / (m.replace(".", "/") + "/__init__.pyc") for m in info["app_modules"]]
        for pyc in targets:
            if pyc.exists():
                s = pyc_symbols(pyc)
                if s:
                    sym[str(pyc.relative_to(out))] = s
                if external:
                    for tool in ("pycdc", "decompyle3", "uncompyle6"):
                        if shutil.which(tool):
                            dst = pyc.with_suffix(".py")
                            args = [str(pyc)] if tool == "pycdc" else ["-o", str(dst), str(pyc)]
                            run_tool(tool, args, dst if tool == "pycdc" else out / "decompile.log")
                            facts["external"][tool] = "used"
                            break
        facts["python_symbols"] = sym
        if not sym:
            facts["notes"].append("الرموز لم تُقرأ لأن إصدار بايثون الحالي لا يطابق إصدار التطبيق (" + info["python"] + "). شغّل الأداة بنفس الإصدار.")
        if not any(t in facts["external"] for t in ("pycdc", "decompyle3", "uncompyle6")):
            facts["notes"].append("لا يوجد فاك pyc مثبت. ملفات .pyc جاهزة بترويسة صحيحة؛ مرّرها لـ pycdc أو decompyle3.")

    # --- نصوص ومفاتيح ونماذج
    if root.exists():
        facts["tree"] = tree_summary(root) if root.is_dir() else None
        urls, secrets = scan_text_artifacts(root if root.is_dir() else out)
        facts["urls"] = [u for u, _ in urls.most_common(60)]
        if secrets:
            facts["warnings"].append(f"عُثر على {len(secrets)} مفتاح/سر مضمّن في التطبيق (مخفي جزئيا). غيّر هذه المفاتيح واستبدلها بإعدادات خارجية.")
        facts["secrets"] = secrets[:40]
        models = find_models(root) if root.is_dir() else []
        if kind == "pe" and target.stat().st_size > 0:
            pass
        facts["models"] = [inspect_model(m) for m in models]
        if copy_models and models:
            md = out / "models"
            md.mkdir(exist_ok=True)
            for m in models:
                src = Path(m["path"])
                shutil.copy2(src, md / src.name)
    facts["stack"] = sorted(set(facts["stack"]))
    (out / "spec.json").write_text(json.dumps(facts, indent=2, ensure_ascii=False, default=str), encoding="utf8")
    (out / "report.md").write_text(render_report(facts), encoding="utf8")
    return facts


REBUILD = {
    "Android native (Java/Kotlin)": ["أنشئ مشروع Android Studio بنفس package وminSdk", "انسخ res/ و AndroidManifest من apktool", "استخدم مخرجات jadx كمرجع لإعادة كتابة الـ logic (المخرجات تحتاج مراجعة)"],
    "Flutter": ["الواجهة والمنطق داخل libapp.so (Dart AOT) ولا يمكن استرجاعه كاملا", "انسخ assets/flutter_assets (الصور والخطوط والترجمات)", "أعد كتابة الكود في مشروع Flutter جديد مسترشدا بالـ spec"],
    "React Native (JS قابل للقراءة)": ["index.android.bundle نص JS: انسخه، واعمل له source-map/prettier لتقرأه"],
    "React Native (Hermes bytecode)": ["الـ bundle بايت كود Hermes: يحتاج أداة فك hbc مخصصة"],
    "Electron": ["انسخ app.asar المستخرج كمشروع npm (package.json موجود غالبا)", "الكود غالبا JS قابل للقراءة"],
    "Python bytecode": ["فك pyc ثم أعد تنظيم المشروع (requirements + entry point)"],
    "PyInstaller": ["افحص pyinstaller/scripts و modules، فك .pyc، ثم استنتج requirements من modules الخارجية"],
    ".NET": ["استخدم ilspycmd لاسترجاع مشروع C# (يعطي قريبا جدا من الأصل)"],
    "Unity IL2CPP": ["استعد الأصول؛ منطق C# مترجم لـ native ولا يرجع كاملا"],
}


def render_report(f):
    L = [f"# تقرير reforge: {Path(f['target']).name}", "",
         f"- النوع: **{f['kind']}**  |  الحجم: {human(f['size']) if f['size'] else '-'}",
         f"- SHA-256: `{f['sha256']}`" if f.get("sha256") else "",
         f"- التقنيات المكتشفة: {', '.join(f['stack']) or 'غير محدد'}", ""]
    if f["warnings"]:
        L += ["## تحذيرات"] + [f"- ⚠️ {w}" for w in f["warnings"]] + [""]
    a = f.get("android")
    if a:
        L += ["## Android", f"- package: `{a['package']}`  |  version: {a['version_name']} ({a['version_code']})",
              f"- minSdk {a['min_sdk']} / targetSdk {a['target_sdk']}",
              f"- activities: {len(a['activities'])}, services: {len(a['services'])}, receivers: {len(a['receivers'])}, providers: {len(a['providers'])}",
              "- permissions: " + (", ".join(p.split('.')[-1] for p in a["permissions"]) or "لا يوجد"), ""]
        L += ["### Activities"] + [f"- `{x}`" for x in a["activities"][:30]] + [""]
    if f.get("pe"):
        p = f["pe"]
        L += ["## PE", f"- {p['machine']}, {'DLL' if p['is_dll'] else 'EXE'}, .NET={p['dotnet']}, sections: {', '.join(p['sections'])}", ""]
    if f.get("pyinstaller"):
        p = f["pyinstaller"]
        L += ["## PyInstaller", f"- Python {p['python']}, عناصر الأرشيف: {p['entries']}",
              f"- سكربتات الدخول: {', '.join(p['scripts']) or '-'}",
              f"- وحدات يُرجّح أنها كود التطبيق ({len(p['app_modules'])}): {', '.join(p['app_modules'][:40])}",
              "- أكبر الحزم داخل PYZ: " + ", ".join(f"{k}({v})" for k, v in list(p["toplevel"].items())[:15]), ""]
    if f.get("python_symbols"):
        L += ["### رموز مستخرجة من الكود"]
        for k, s in list(f["python_symbols"].items())[:15]:
            L += [f"- `{k}`: {', '.join(s['names'][:25])}"]
        L += [""]
    if f.get("tree"):
        t = f["tree"]
        L += ["## محتوى الحزمة", f"- {t['files']} ملف، {human(t['bytes'])}", "- الامتدادات: " + ", ".join(f"{k}:{v}" for k, v in list(t["by_ext"].items())[:12]),
              "- أكبر الملفات:"] + [f"  - `{x['path']}` ({human(x['size'])})" for x in t["largest"][:8]] + [""]
    if f.get("models"):
        L += ["## نماذج الذكاء الاصطناعي"]
        for m in f["models"]:
            d = m.get("detail", {})
            brief = ", ".join(f"{k}={v}" for k, v in d.items() if k in ("tensors", "parameters", "architecture", "name", "opset", "initializers", "note", "error", "tensor_blobs"))
            L += [f"- `{m['rel']}` — {m['format']} ({human(m['size'])}) {brief}"]
        L += [""]
    if f.get("urls"):
        L += ["## نقاط اتصال (URLs)"] + [f"- {u}" for u in f["urls"][:25]] + [""]
    if f.get("secrets"):
        L += ["## أسرار مضمّنة (مخفية)"] + [f"- {s['type']} في `{s['file']}`: {s['masked']}" for s in f["secrets"][:15]] + [""]
    if f["notes"]:
        L += ["## ملاحظات"] + [f"- {n}" for n in f["notes"]] + [""]
    steps = []
    for s in f["stack"] + ([f["kind"]] if f["kind"] in REBUILD else []):
        steps += REBUILD.get(s, [])
    if "pyinstaller" in f:
        steps += REBUILD["PyInstaller"]
    if steps:
        L += ["## خطة إعادة البناء المقترحة"] + [f"{i}. {s}" for i, s in enumerate(dict.fromkeys(steps), 1)] + [""]
    ext = {k: v for k, v in f["external"].items()}
    L += ["## أدوات خارجية", ", ".join(f"{k}: {'غير مثبت' if v is None else v}" for k, v in ext.items()) or "لم تُستدعَ"]
    return "\n".join(x for x in L if x is not None)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="reforge", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("target")
    a.add_argument("-o", "--out", default="reforge_out")
    a.add_argument("--no-external", action="store_true", help="لا تستدعِ jadx/apktool/...")
    a.add_argument("--no-copy-models", action="store_true")
    m = sub.add_parser("models")
    m.add_argument("path")
    m.add_argument("--json", action="store_true")
    sub.add_parser("doctor")
    ns = ap.parse_args(argv)

    if ns.cmd == "doctor":
        for t, d in EXTERNAL_TOOLS.items():
            print(f"{'✔' if shutil.which(t) else '✘'} {t:12} {d}")
        return 0
    if ns.cmd == "models":
        p = Path(ns.path)
        ms = find_models(p) if p.is_dir() else [e for e in [sniff_model(p)] if e]
        for e in ms:
            e.setdefault("rel", p.name)
            inspect_model(e)
        if ns.json:
            print(json.dumps(ms, indent=2, ensure_ascii=False, default=str))
        else:
            for e in ms:
                d = e.get("detail", {})
                print(f"{e['rel']}: {e['format']} {human(e['size'])}")
                for k, v in d.items():
                    if k != "tensor_list":
                        print(f"   {k}: {str(v)[:200]}")
        return 0
    t = Path(ns.target)
    if not t.exists():
        print("الهدف غير موجود", file=sys.stderr)
        return 2
    f = analyze(t, Path(ns.out), external=not ns.no_external, copy_models=not ns.no_copy_models)
    print(f"✔ النوع: {f['kind']} | التقنيات: {', '.join(f['stack']) or '-'}")
    print(f"✔ التقرير: {Path(ns.out) / 'report.md'}\n✔ المواصفات: {Path(ns.out) / 'spec.json'}")
    for w in f["warnings"]:
        print("⚠", w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
