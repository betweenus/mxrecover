#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mxrecover - recovery of H.264+AAC video from an mxv-damaged file.

An mxv file is a fake-codec scam: it disguises itself as an ordinary
MP4 (ftyp, 'mxv ' marker, moov, free, mdat), but the real media data is
not in the MP4 boxes - it is stored in an AES-128-ECB-encrypted EBML
segment inside the mdat payload. Files of this kind are produced when a
video is saved from a certain crapware video player.

This is not DRM or copy protection. The player encrypts the videos the
user saves, so the files can be played by that player only - the same
trick as ransomware, which encrypts files and demands money to unlock
them. The "protection" is fake: the keys are stored in plaintext in
the file itself, so the only effect of the encryption is to damage
the user's content and push the user to keep the player. The player
also inserts a 9-second fake stub - the only part of the media left
unencrypted. mxrecover undoes the damage.

Container layout:

    ftyp + 'mxv ' marker + moov + free + mdat, where the mdat payload
    contains:
      * a 9-second fake stub;
      * an EBML segment: the header is plaintext (codec ids, per-track
        keys, codec configs, durations); the cluster Block payloads are
        encrypted with AES-128-ECB.

File format markers:
    * EBML segment  - signature 19 54 EE B2;
    * track key     - element 56 D1 (b64, 24 B + NUL);
    * track number  - element 92 81 <n>;
    * codec config  - element 72 B1 (AAC AudioSpecificConfig in the
                      audio track, SPS/PPS in the video track);
    * durations     - "HH:MM:SS.fffffff" strings in the Info element;
    * Cues element  - 1B 62 CA 7A.

Crypto: `cryptography` (AES-128-ECB); see requirements.txt.
Usage:  mxrecover.py <command> [args]   -   see `mxrecover.py help`.
"""
import sys, os, re, struct, hashlib, json, faulthandler
faulthandler.enable()

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit(
        'error: module `cryptography` is not installed.\n'
        '  apt install python3-cryptography\n'
        '  (or: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)')

# ==================== constants ====================
SEG_ID   = 0x1954EEB2    # EBML segment signature (plaintext)
CLUSTER  = 0x1E52C584    # EBML Cluster
CUES_ID  = 0x1B62CA7A    # EBML Cues (end of the cluster tape)
AAC_SPS  = [96000, 88200, 64000, 48000, 44100, 32000,
            24000, 22050, 16000, 12000, 11025, 8000, 7350]
STD_FPS  = (23.976, 24.0, 25.0, 29.97, 30.0, 48.0, 50.0, 59.94, 60.0, 120.0)
B64_RE   = re.compile(rb'^[A-Za-z0-9+/]{16,24}={0,2}\x00$')
# profile_idc names per ISO/IEC 14496-10, Table A.1
PROF     = {42: 'CAVLC 4:4:4 Intra', 44: 'Baseline Constrained',
            46: 'Reserved', 48: 'Scalable Constrained Baseline',
            49: 'Scalable Constrained High', 50: 'Scalable High',
            66: 'Baseline', 77: 'Main', 88: 'Extended', 100: 'High',
            110: 'High 10', 118: 'High 4:2:2', 120: 'High 4:4:4 Predictive',
            122: 'Scalable Baseline', 128: 'Scalable High Intra',
            132: 'Scalable Constrained Baseline', 134: 'Scalable High',
            135: 'Progressive High Intra', 138: 'Progressive High',
            139: 'Progressive High Intra', 144: 'AVC High Intra'}

# ==================== AES-128-ECB (cryptography) ====================
def aes_ecb(data, key, decrypt=False):
    if not data:
        return b''
    op = (Cipher(algorithms.AES(key), modes.ECB()).decryptor() if decrypt
          else Cipher(algorithms.AES(key), modes.ECB()).encryptor())
    return op.update(data) + op.finalize()

# ==================== EBML vint ====================
def vint_len(x):
    return 1 if x >= 0x80 else 2 if x >= 0x40 else 3 if x >= 0x20 else 4 if x >= 0x10 else 8

def read_vint(b, o):
    n = vint_len(b[o])
    return int.from_bytes(b[o:o+n], 'big') & ((1 << (7*n)) - 1), n

# ==================== segment search + plaintext header parse ====================
def find_segment(data):
    """Offset of the EBML segment (unique signature 19 54 EE B2)."""
    sig = SEG_ID.to_bytes(4, 'big')
    T = data.find(sig)
    if T < 0:
        raise SystemExit('error: EBML segment signature 1954EEB2 not found')
    if T > 0 and data[T-4:T] == sig:
        T -= 4  # guard against a 4-byte misalignment
    return T

def parse_header(data, T):
    """Parse the plaintext segment header (T .. first cluster):
    per-track codec/key/track number, durations, encoder.
    Returns (first_cluster_off, header, tracks, durations, encoders)."""
    fc = data.find(b'\x1e\x52\xc5\x84', T + 4)
    if fc < 0 or fc - T > 0x10000:
        raise SystemExit('error: first cluster 1E52C584 not found')
    s, sl = read_vint(data, fc + 4)
    if not (0 < s < 1 << 20):
        raise SystemExit(f'error: first cluster @0x{fc:x} has implausible size={s}')
    header = data[T:fc]

    tracks = []          # dict(codec, key, track_no)
    last_codec, last_rec = None, -1
    i, H = 0, len(header)
    while i < H:
        # CodecID: 95 <sz> <ascii sz>
        if header[i] == 0x95 and i + 1 < H:
            sz = read_vint(header, i + 1)[0]
            if 1 <= sz <= 32 and i + 2 + sz <= H:
                body = header[i + 2:i + 2 + sz]
                if all(32 <= c < 127 for c in body):
                    last_codec = body.decode('ascii')
                    i += 2 + sz
                    continue
        # key: 56 D1 <sz> <b64 + NUL>
        if header[i] == 0x56 and i + 2 < H and header[i + 1] == 0xD1:
            sz, sl2 = read_vint(header, i + 2)
            if i + 2 + sl2 + sz <= H:
                body = header[i + 2 + sl2:i + 2 + sl2 + sz]
                if B64_RE.match(body) and last_codec:
                    tracks.append(dict(codec=last_codec,
                                       key=_b64decode(body[:-1]),
                                       track_no=None))
                    last_rec = len(tracks) - 1
                    i += 2 + sl2 + sz
                    continue
        # track number: 92 81 <n> (follows the key element)
        if header[i] == 0x92 and i + 2 < H and header[i + 1] == 0x81:
            if 0 <= last_rec < len(tracks) and tracks[last_rec]['track_no'] is None:
                tracks[last_rec]['track_no'] = header[i + 2]
                last_rec = -1
            i += 3
            continue
        # codec config: 72 B1 <sz> <body>
        # the video track carries the SPS/PPS blob; the audio track
        # carries a 2-byte AAC AudioSpecificConfig (aot=2, AAC-LC)
        if header[i] == 0x72 and i + 2 < H and header[i + 1] == 0xB1:
            sz, sl3 = read_vint(header, i + 2)
            if (header[i + 2] & 0x80) and 2 <= sz < 512 and i + 2 + sl3 + sz <= H:
                if sz == 2 and last_codec and last_codec.startswith('A_'):
                    b0, b1 = header[i + 2 + sl3:i + 4 + sl3]
                    aot = (b0 >> 3) & 0x1F
                    fidx = ((b0 & 7) << 1) | (b1 >> 7)
                    chan = (b1 >> 3) & 0xF
                    if aot == 2 and fidx < len(AAC_SPS) and 1 <= chan <= 8:
                        for t in reversed(tracks):
                            if t['codec'] == last_codec:
                                t['acfg'] = (AAC_SPS[fidx], chan)
                                break
                i += 2 + sl3 + sz
                continue
        i += 1

    durations = []
    for m in re.finditer(rb'(\d{2}):(\d{2}):(\d{2})\.(\d{7,9})', header):
        durations.append(int(m.group(1))*3600 + int(m.group(2))*60 +
                         int(m.group(3)) + int(m.group(4)) / 10**len(m.group(4)))
    encoders = [s.decode('ascii', 'replace') for s in re.findall(rb'[\x20-\x7e]{6,40}', header)
                if s.startswith(b'Lavf')]
    return fc, header, tracks, durations, encoders

def _b64decode(b):
    import base64
    k = base64.b64decode(b)
    if len(k) != 16:
        raise SystemExit(f'error: key from file is not 16 bytes: {len(k)}')
    return k

# ==================== clusters: blocks up to Cues ====================
def extract_blocks(data, start, verbose=True):
    """Walk the top-level elements from start and collect the EBML Blocks.
    Non-cluster elements are skipped; the walk stops at Cues or EOF.
    Returns (blocks, cues, noncluster)."""
    blocks, noncluster, cues = [], 0, None
    o, n = start, len(data)
    while o < n:
        x = data[o]
        il = 4 if x >= 0x10 else 8
        eid = int.from_bytes(data[o:o+il], 'big')
        s, sl = read_vint(data, o + il)
        d = o + il + sl
        if d + s > n:
            raise SystemExit(f'error: element @0x{o:x} size=0x{s:x} exceeds EOF')
        if eid != CLUSTER:
            if eid == CUES_ID:
                cues = (o, s)
                break
            noncluster += 1
            o = d + s
            continue
        c, cend, cts = d, d + s, 0
        while c < cend:
            j = data[c]
            sj, slj = read_vint(data, c + 1)
            dd = c + 1 + slj
            if j == 0xF6:
                cts = int.from_bytes(data[dd:dd+sj], 'big')
            elif j == 0xB2:
                blocks.append(dict(tr=data[dd], cts=cts,
                                   bts=int.from_bytes(data[dd+1:dd+3], 'big'),
                                   fl=data[dd+3], d=dd+4, dlen=sj-4))
            c = dd + sj
        o = cend
    if verbose:
        if cues:
            print(f'  Cues @ 0x{cues[0]:x} ({cues[1]} B)')
        if noncluster:
            print(f'  NOTE: {noncluster} non-cluster top-level elements skipped')
        if not cues:
            print('  NOTE: Cues not found, walked to EOF')
    return blocks, cues, noncluster

def decrypt_pkt(data, p, L, key):
    """Decrypt a block payload: whole 16-byte blocks + any tail as-is."""
    nb = (L // 16) * 16
    return aes_ecb(data[p:p+nb], key, True) + data[p+nb:p+L]

def avcc_to_annexb(pt):
    out = bytearray()
    i = 0
    while i + 4 <= len(pt):
        ln = int.from_bytes(pt[i:i+4], 'big')
        out += b'\x00\x00\x01' + pt[i+4:i+4+ln]
        i += 4 + ln
    if i != len(pt):
        raise SystemExit(f'error: AVCC tail: {len(pt)-i} extra bytes')
    return bytes(out)

def snap_fps(fps):
    """Nearest standard frame rate within 0.1%, or None."""
    cands = [sf for sf in STD_FPS if abs(fps - sf) / sf < 0.001]
    return min(cands, key=lambda sf: abs(fps - sf)) if cands else None

def snap_rate(f):
    """Nearest sample rate from the AAC table."""
    return f if f in AAC_SPS else min(AAC_SPS, key=lambda x: abs(x - f))

# ==================== H.264 SPS parsing ====================
class _BR:
    __slots__ = ('d', 'o', 'b')
    def __init__(s, d): s.d, s.o, s.b = d, 0, 0
    def pos(s): return s.o*8 + s.b
    def bit(s):
        v = (s.d[s.o] >> (7-s.b)) & 1; s.b += 1
        if s.b == 8: s.b, s.o = 0, s.o + 1
        return v
    def u(s, k):
        v = 0
        for _ in range(k): v = (v << 1) | s.bit()
        return v
    def ue(s):
        z = 0
        while s.bit() == 0: z += 1
        return 0 if z == 0 else (1 << z) - 1 + s.u(z)
    def se(s):
        n = s.ue()
        return (n + 1)//2 if n % 2 else -n//2

def parse_sps(payload):
    r = _BR(payload)
    prof = r.u(8)
    flags = 0
    for i in range(6): flags |= r.bit() << i
    r.u(2)
    lvl = r.u(8)
    sps_id = r.ue()
    high = prof in (100,110,120,244,44,83,86,118,122,132,134,135,138,139,144)
    if high:
        chroma = r.ue()
        if chroma == 3: r.bit()
        bdl = r.ue() + 8
        bdc = r.ue() + 8
        r.bit()
        spm = r.bit()
        if spm:
            for _ in range(4 + (2 if chroma else 0)):
                for _ in range(16):
                    v = r.u(12); m = 1 << 11
                    _ = v - m if v >= m else v + m
    else:
        chroma, bdl, bdc, spm = 1, 8, 8, 0
    lmf = r.ue()
    max_fn = 1 << (lmf + 4)
    poc_type = r.ue()
    max_poc_lsb = None
    if poc_type == 0:
        lmp = r.ue()
        max_poc_lsb = 1 << (lmp + 4)
    elif poc_type == 1:
        r.bit(); r.se(); r.se()
        pcl = r.ue()
        for _ in range(pcl): r.se()
    rfc = r.ue()
    gaps = r.bit()
    mw = r.ue() + 1
    mh = r.ue() + 1
    fmo = r.bit()
    if not fmo: r.bit()
    d8 = r.bit()
    crop = r.bit()
    cl = cr = ct = cb = 0
    if crop:
        cl = r.ue(); cr = r.ue(); ct = r.ue(); cb = r.ue()
    vui = r.bit()
    if vui:
        ari = r.bit()
        if ari:
            ar = r.u(8)
            if ar == 255: r.ue(); r.ue()
        oi = r.bit()
        if oi: r.bit()
        vsi = r.bit()
        if vsi:
            r.u(3); r.bit(); r.u(3); r.u(3); r.u(3)
            cd = r.bit()
            if cd: r.u(3); r.u(3); r.u(3); r.ue(); r.ue()
        ti = r.bit()
        if ti: r.u(32); r.u(32); r.bit()
        br = r.bit()
        if br: r.bit(); r.u(5); r.u(5); r.u(5); r.bit()
    w = mw * 16
    h = mh * (2 if not fmo else 1) * 16
    if crop:
        w -= 2*(cl + cr); h -= 2*(ct + cb)
    return dict(prof=prof, flags=flags, lvl=lvl, sps_id=sps_id,
                chroma=chroma, bdl=bdl, bdc=bdc,
                max_fn=max_fn, poc_type=poc_type, max_poc_lsb=max_poc_lsb,
                rfc=rfc, gaps=gaps, mw=mw, mh=mh, fmo=fmo,
                d8=d8, crop=crop, w=w, h=h, vui=vui, payload=payload)

def sps_pps_from_header(header):
    """SPS/PPS stored in the plaintext segment header as
    [u16 len][0x67 NAL] ... [u16 len][0x68 NAL].
    Returns (sps_nal, pps_nal) or None."""
    H = len(header)
    k = 0
    while k < H:
        if header[k] == 0x67 and k >= 2:
            ln = int.from_bytes(header[k-2:k], 'big')
            if 5 <= ln <= 512 and k + ln <= H:
                cand = header[k:k+ln]
                try:
                    sps = parse_sps(cand[1:])
                    if 16 <= sps['w'] <= 8192 and 16 <= sps['h'] <= 8192:
                        q = k + ln
                        while q + 4 <= H and q - (k + ln) < 16:
                            if header[q] == 0x68:
                                pln = int.from_bytes(header[q-2:q], 'big')
                                if 3 <= pln <= 256 and q + pln <= H:
                                    return cand, header[q:q+pln]
                            q += 1
                        return cand, None
                except Exception:
                    pass
                k += ln
                continue
        k += 1
    return None

# ==================== slice parsing and POC ====================
_PPICT = {0:'P', 1:'B', 2:'I', 3:'S', 4:'S'}

def parse_slices_and_poc(nals, sps, unit):
    """Parse the VCL slices, compute the presentation order (POC) and
    return the display order plus pts/dts in `unit` ticks of the
    video timescale."""
    MAX_FN   = sps['max_fn']
    MAX_POC  = sps['max_poc_lsb']
    LOG2_FN  = MAX_FN.bit_length() - 1
    LOG2_POC = MAX_POC.bit_length() - 1
    assert sps['poc_type'] == 0, f"poc_type={sps['poc_type']} not supported"
    assert sps['fmo'], 'frame_mbs_only must be 1'

    st = {'prev_fn': 0, 'prev_fno': 0, 'prev_msb': 1 << 16, 'prev_lsb': -1}
    frames = []
    for idx, nal in enumerate(nals):
        t = nal[0] & 0x1F
        if t not in (1, 5): continue
        ref_idc = (nal[0] >> 5) & 3
        r = _BR(nal)
        r.u(8)              # nal header
        r.ue()              # first_mb_in_slice
        st_raw = r.ue()
        if st_raw > 9:
            raise ValueError(f'nal {idx}: slice_type {st_raw} > 9')
        pict = _PPICT[st_raw - 5 if st_raw > 4 else st_raw]
        if t == 5 and pict != 'I':
            raise ValueError(f'nal {idx}: non-intra slice in IDR NAL')
        r.ue()              # pps_id
        fn = r.u(LOG2_FN)
        if t == 5:
            r.ue()          # idr_pic_id
            st.update(prev_fn=0, prev_fno=0, prev_msb=1 << 16, prev_lsb=-1)
        plsb = r.u(LOG2_POC)
        fno = st['prev_fno']
        if fn < st['prev_fn']: fno += MAX_FN
        if st['prev_lsb'] < 0: st['prev_lsb'] = plsb
        if plsb < st['prev_lsb'] and st['prev_lsb'] - plsb >= MAX_POC // 2:
            msb = st['prev_msb'] + MAX_POC
        elif plsb > st['prev_lsb'] and st['prev_lsb'] - plsb < -MAX_POC // 2:
            msb = st['prev_msb'] - MAX_POC
        else:
            msb = st['prev_msb']
        poc = msb + plsb
        droppable = (ref_idc == 0)
        if not droppable:
            st['prev_msb'], st['prev_lsb'] = msb, plsb
        st['prev_fno'], st['prev_fn'] = fno, fn
        frames.append(dict(type=t, ref_idc=ref_idc, pict=pict,
                           fn=fn, plsb=plsb, poc=poc, droppable=droppable))

    N = len(frames)
    gops, g0 = [], 0
    for i in range(1, N + 1):
        if i == N or frames[i]['type'] == 5:
            gops.append((g0, i)); g0 = i
    assert all(frames[a]['type'] == 5 for a, _ in gops), 'GOP without IDR'
    rank = [0]*N
    disp = []
    offset = 0
    for (a, b) in gops:
        idxs = list(range(a, b))
        pocs = [frames[i]['poc'] for i in idxs]
        assert len(set(pocs)) == len(pocs), f'POC not unique in GOP {a}..{b-1}'
        disp_in = sorted(idxs, key=lambda i: frames[i]['poc'])
        for p, i in enumerate(disp_in):
            rank[i] = offset + p
        disp.extend(disp_in)
        offset += b - a

    pts = [unit * rank[k] for k in range(N)]
    dts = [unit * k for k in range(N)]
    off = [pts[k] - dts[k] for k in range(N)]
    return dict(N=N, rank=rank, disp=disp, pts=pts, dts=dts, off=off,
                isidr=[f['type'] == 5 for f in frames], gops=len(gops))

# ==================== audio channel detection ====================
def adts_hdr(plen, freq_idx, aot=1, chan=2):
    flen = 7 + plen
    return bytes([0xFF, 0xF1,
                  ((aot - 1) << 6) | (freq_idx << 2) | ((chan >> 2) & 1),
                  0x00 | ((chan & 3) << 6) | ((flen >> 11) & 3),
                  (flen >> 3) & 0xFF,
                  ((flen & 7) << 5) | 0x1F,
                  0xFC])

def probe_channels(aud, aal, freq, ffmpeg, tmpdir):
    """Detect the channel count (1 or 2) by decoding the first audio
    units with ffmpeg; used when the plaintext header does not carry
    the AAC codec config. Temporary files are created in tmpdir and
    removed afterwards. Returns None on failure."""
    import subprocess, tempfile, array
    n = min(64, len(aal))
    idx = 0
    buf = bytearray()
    for i in range(n):
        buf += adts_hdr(aal[i], AAC_SPS.index(freq), chan=2) + aud[idx:idx + aal[i]]
        idx += aal[i]
    try:
        fd, adts = tempfile.mkstemp(prefix='mxrecover_adts_', suffix='.aac', dir=tmpdir)
    except OSError:
        fd, adts = tempfile.mkstemp(prefix='mxrecover_adts_', suffix='.aac')
    os.close(fd)
    pcm = adts[:-4] + '.s16'
    try:
        with open(adts, 'wb') as f:
            f.write(bytes(buf))
        r = subprocess.run([ffmpeg, '-v', 'error', '-y', '-i', adts, '-f', 's16le', pcm],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f'  NOTE: channel probe failed: {r.stderr.decode()[:120]}')
            return None
        with open(pcm, 'rb') as f:
            d = f.read()
        if len(d) < 4:
            return None
        s = array.array('h')
        s.frombytes(d[:len(d)//2*2])
        lim = min(len(s) // 2, 44100 * 2)
        diff = sum(1 for i in range(lim) if s[2*i] != s[2*i + 1])
        return 2 if diff > lim * 0.005 else 1
    finally:
        for p in (adts, pcm):
            try: os.unlink(p)
            except OSError: pass

# ==================== MP4 muxing ====================
def _u16(v): return struct.pack('>H', v)
def _u32(v): return struct.pack('>I', v)

def _box(typ, *body):
    b = b''.join(body)
    return _u32(8 + len(b)) + typ + b

# 3x3 rotation matrix: [1 0 0] [0 1 0] [0 0 16.0], 36 bytes
_MATRIX = (_u32(0x00010000) + _u32(0) + _u32(0) +
           _u32(0) + _u32(0x00010000) + _u32(0) +
           _u32(0) + _u32(0) + _u32(0x40000000))

def mp4_mux(sps_nal, pps_nal, vcl, vavcc_sizes, aud, aal, poc,
            width, height, vscale, vdur, ascale, chan):
    N   = poc['N']
    na  = len(aal)
    isidr = poc['isidr']

    # video samples: AVCC, SPS/PPS prefixed to every IDR slice
    vid = bytearray()
    vavcc = []
    for x in vcl:
        if (x[0] & 0x1F) == 5:
            smp = (struct.pack('>I', len(sps_nal)) + sps_nal +
                   struct.pack('>I', len(pps_nal)) + pps_nal +
                   struct.pack('>I', len(x)) + x)
        else:
            smp = struct.pack('>I', len(x)) + x
        vavcc.append(len(smp))
        vid += smp
    assert vavcc == vavcc_sizes, 'vavcc size mismatch'
    vid = bytes(vid)

    a_total = na * 1024
    v_total = N * vdur
    mv_dur  = max(v_total, (a_total * vscale + ascale - 1) // ascale)

    # avcC (configuration version 1)
    avcC = (b'\x01' + bytes([sps_nal[1], 0, sps_nal[3], 0xFF]) +
            b'\xe1' + _u16(len(sps_nal)) + sps_nal +
            b'\x01' + _u16(len(pps_nal)) + pps_nal)
    avc1 = (b'\x00' * 4 + _u16(0) + _u16(1) + b'\x00' * 16 +
            _u16(width) + _u16(height) +
            _u32(0x00480000) + _u32(0x00480000) +
            _u32(0) + _u16(1) + b'\x00' * 32 + _u16(0x0018) + _u16(0xFFFF) +
            _box(b'avcC', avcC))
    stsd_v = _box(b'stsd', b'\x00\x00\x00\x00', _u32(1),
                  _u32(8 + len(avc1)) + b'avc1' + avc1)
    stts_v = _box(b'stts', b'\x00\x00\x00\x00', _u32(1), _u32(N), _u32(vdur))
    kf = [i + 1 for i in range(N) if isidr[i]]
    stss = _box(b'stss', b'\x00\x00\x00\x00', _u32(len(kf)), *map(_u32, kf))
    stsc_v = _box(b'stsc', b'\x00\x00\x00\x00', _u32(1), _u32(1), _u32(N), _u32(1))
    stsz_v = _box(b'stsz', b'\x00\x00\x00\x00', _u32(0), _u32(N), *map(_u32, vavcc))
    off = poc['off']
    runs = []
    for o in off:
        if runs and runs[-1][1] == o:
            runs[-1][0] += 1
        else:
            runs.append([1, o])
    ctts = _box(b'ctts', b'\x00\x00\x00\x00', _u32(len(runs)),
                *[_u32(c) + _u32(o & 0xFFFFFFFF) for c, o in runs])

    # AudioSpecificConfig: AAC-LC, sample frequency and channel count
    _f = AAC_SPS.index(ascale)
    vos = bytes([(2 << 3) | (_f >> 1), (_f & 1) << 7 | chan << 3])
    avgb = (len(aud) * 8 * ascale + a_total - 1) // a_total
    maxb = avgb * 2
    def _desc(tag, ln):
        return bytes([tag, (ln >> 21) | 0x80, (ln >> 14) | 0x80,
                      (ln >> 7) | 0x80, ln & 0x7F])
    esdd = (_desc(0x04, 13 + 5 + len(vos)) + b'\x40\x15' + b'\x00\x00\x00' +
            _u32(maxb) + _u32(avgb) + _desc(0x05, len(vos)) + vos)
    esdl = _desc(0x06, 1) + b'\x02'
    esd  = (_desc(0x03, 3 + 5 + 13 + 5 + len(vos) + 5 + 1) +
            _u16(0) + b'\x00' + esdd + esdl)
    esds = _box(b'esds', b'\x00\x00\x00\x00', esd)
    mp4a = (b'\x00' * 4 + _u16(0) + _u16(1) + _u16(0) + _u16(0) +
            _u32(0) + _u16(chan) + _u16(16) + _u16(0) + _u16(0) +
            _u32(ascale << 16) + esds)
    stsd_a = _box(b'stsd', b'\x00\x00\x00\x00', _u32(1),
                  _u32(8 + len(mp4a)) + b'mp4a' + mp4a)
    stts_a = _box(b'stts', b'\x00\x00\x00\x00', _u32(1), _u32(na), _u32(1024))
    stsc_a = _box(b'stsc', b'\x00\x00\x00\x00', _u32(1), _u32(1), _u32(na), _u32(1))
    stsz_a = _box(b'stsz', b'\x00\x00\x00\x00', _u32(0), _u32(na), *map(_u32, aal))

    def _mdhd(ts, dur):
        return _box(b'mdhd', b'\x00\x00\x00\x00', _u32(0), _u32(0),
                    _u32(ts), _u32(dur), _u16(0x55C4) + _u16(0))

    hdlr_v = _box(b'hdlr', b'\x00\x00\x00\x00', _u32(0), b'vide', b'\x00' * 12, b'VideoHandler\x00')
    hdlr_a = _box(b'hdlr', b'\x00\x00\x00\x00', _u32(0), b'soun', b'\x00' * 12, b'SoundHandler\x00')
    dref   = _box(b'dref', b'\x00\x00\x00\x00', _u32(1), _box(b'url ', _u32(1)))
    vmhd   = _box(b'vmhd', b'\x00\x00\x00\x01', _u16(0) + _u16(0) * 3)
    smhd   = _box(b'smhd', b'\x00\x00\x00\x00', _u16(0) + _u16(0))

    def _tkhd(tid, dur, vol, w, h, br):
        return _box(b'tkhd', b'\x00\x00\x00\x03', _u32(0), _u32(0), _u32(tid), _u32(0),
                    _u32(dur), b'\x00' * 8, _u16(0) + _u16(0) + _u16(vol) + _u16(0),
                    _MATRIX, struct.pack('>I', int(w * 65536)),
                    struct.pack('>I', int(h * 65536)), _u32(br))
    tk_v = _tkhd(1, v_total, 0, width, height, len(vid) * 8 * vscale // v_total)
    tk_a = _tkhd(2, a_total, 0x0100, 0, 0, avgb)

    ftyp = _box(b'ftyp', b'isom', _u32(512), b'isomiso2avc1mp41')

    def _stco(offs):
        return _box(b'stco', b'\x00\x00\x00\x00', _u32(1), _u32(offs))

    # reserve 40 bytes for the two stco boxes (the moov size must
    # be known before the offsets are written)
    stbl_v0 = _box(b'stbl', stsd_v, stts_v, stss, stsc_v, stsz_v, ctts)
    stbl_a0 = _box(b'stbl', stsd_a, stts_a, stsc_a, stsz_a)
    minf_v0 = _box(b'minf', vmhd, _box(b'dinf', dref), stbl_v0)
    minf_a0 = _box(b'minf', smhd, _box(b'dinf', dref), stbl_a0)
    mdia_v0 = _box(b'mdia', _mdhd(vscale, v_total), hdlr_v, minf_v0)
    mdia_a0 = _box(b'mdia', _mdhd(ascale, a_total), hdlr_a, minf_a0)
    mvhd_s = _box(b'mvhd', b'\x00\x00\x00\x00', _u32(0), _u32(0),
                  _u32(vscale), _u32(mv_dur), _u32(0x00010000),
                  _u16(0x0100) + _u16(0) + b'\x00' * 8 + _MATRIX +
                  b'\x00' * 24 + _u32(3))
    moov_inner = len(mvhd_s) + len(_box(b'trak', tk_v, mdia_v0)) + \
                 len(_box(b'trak', tk_a, mdia_a0))
    mdat_off = len(ftyp) + (8 + moov_inner + 40) + 8
    stco_v = _stco(mdat_off)
    stco_a = _stco(mdat_off + len(vid))
    stbl_v = _box(b'stbl', stsd_v, stts_v, stss, stsc_v, stsz_v, stco_v, ctts)
    stbl_a = _box(b'stbl', stsd_a, stts_a, stsc_a, stsz_a, stco_a)
    minf_v = _box(b'minf', vmhd, _box(b'dinf', dref), stbl_v)
    minf_a = _box(b'minf', smhd, _box(b'dinf', dref), stbl_a)
    mdia_v = _box(b'mdia', _mdhd(vscale, v_total), hdlr_v, minf_v)
    mdia_a = _box(b'mdia', _mdhd(ascale, a_total), hdlr_a, minf_a)
    moov   = _box(b'moov', mvhd_s, _box(b'trak', tk_v, mdia_v),
                  _box(b'trak', tk_a, mdia_a))
    assert len(moov) == 8 + moov_inner + 40, 'moov size mismatch'
    mdat = _box(b'mdat', vid, aud)
    return ftyp + moov + mdat

# ==================== NAL ====================
def split_nals(data):
    """Split an Annex-B stream into NAL payloads (start codes removed)."""
    n = len(data)
    scs = []
    p = data.find(b'\x00\x00\x01')
    while p >= 0:
        scs.append(p)
        p = data.find(b'\x00\x00\x01', p + 3)
    nals = []
    for a, b in zip(scs, scs[1:] + [n]):
        s = a + (4 if data[a:a+4] == b'\x00\x00\x00\x01' else 3)
        nals.append(data[s:b])
    return nals

# ==================== ffmpeg / ffprobe ====================
def _find_tool(name):
    p = os.path.join('/usr/bin', name)
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    return name

def find_ffprobe(): return _find_tool('ffprobe')
def find_ffmpeg():  return _find_tool('ffmpeg')

def ffprobe_info(path):
    """Run ffprobe with full frame and packet counting; return the
    parsed JSON (nb_read_frames / nb_read_packets arrive as strings)."""
    import subprocess
    r = subprocess.run([find_ffprobe(), '-v', 'error', '-count_frames',
                        '-count_packets', '-show_streams', '-show_format',
                        '-of', 'json', path],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit(f'error: ffprobe failed on {path}: {r.stderr.strip()[:200]}')
    return json.loads(r.stdout)

# ==================== container / mdat layout ====================
def container_map(data):
    """Top-level boxes before the mdat box and the mdat offset.
    A box with a broken size field is treated as an opaque 8-byte marker.
    Returns (list of (off, type|None, size), mdat_off)."""
    pre = []
    o, n = 0, len(data)
    while o + 8 <= n:
        sz = int.from_bytes(data[o:o+4], 'big')
        typ = data[o+4:o+8]
        if typ == b'mdat':
            return pre, o
        if 8 <= sz <= n - o:
            pre.append((o, typ, sz))
            o += sz
        else:
            pre.append((o, None, 8))   # opaque 8-byte marker (e.g. 'mxv ')
            o += 8
    return pre, None

def ftyp_brands(data, off, sz):
    body = data[off+8:off+sz]
    if len(body) < 8:
        return None, []
    major = body[:4].decode('latin-1')
    brands, rest = [], body[8:]
    while len(rest) >= 4:
        brands.append(rest[:4].decode('latin-1'))
        rest = rest[4:]
    return major, brands

def analyze_stub(data, mdat_off, T):
    """The chunk table after the mdat header describes the 9-second
    fake stub. Returns dict(off, ln, nals, idr), or None if the stub
    is not present."""
    tbl = mdat_off + 8
    if tbl + 8 > len(data):
        return None
    off = int.from_bytes(data[tbl:tbl+4], 'big')
    ln  = int.from_bytes(data[tbl+4:tbl+8], 'big')
    if not (0 < ln < 1 << 28) or off > ln:
        return None
    start = tbl + 8 + off
    end = start + ln
    if not (T - 16 <= end <= T + 16):
        return None                  # the stub must stop at the segment
    upper = min(end, T)
    nals = idr = 0
    i = start
    while i + 4 < upper:
        l = int.from_bytes(data[i:i+4], 'big')
        if l < 1 or i + 4 + l > upper:
            return None              # not a valid AVCC stream -> no stub
        if data[i+4] & 0x1F == 5:
            idr += 1
        nals += 1
        i += 4 + l
    if i != upper or nals < 2:
        return None
    return dict(off=start, ln=upper - start, nals=nals, idr=idr)

# ==================== source loading ====================
def load_source(path):
    """Read the source file and parse the plaintext parts: the EBML header
    (tracks, keys, codec config, durations), the block records and the
    per-track split."""
    if not os.path.isfile(path):
        raise SystemExit(f'error: file not found: {path}')
    data = open(path, 'rb').read()
    T = find_segment(data)
    fc, header, tracks, durations, encoders = parse_header(data, T)
    vtrack = next((t for t in tracks if t['codec'].startswith('V_')), None)
    atrack = next((t for t in tracks if t['codec'].startswith('A_')), None)
    if not vtrack or not atrack:
        raise SystemExit('error: video (V_*) and/or audio (A_*) track not found in header')
    if vtrack['track_no'] is None or atrack['track_no'] is None:
        raise SystemExit('error: track number (element 92 81) missing in header')
    if len(durations) < 2:
        raise SystemExit(f'error: fewer than 2 durations in header: {durations}')
    v_dur, a_dur = durations[0], durations[1]
    blocks, cues, noncluster = extract_blocks(data, fc, verbose=False)
    v = [b for b in blocks if (b['tr'] & 0x7F) == vtrack['track_no']]
    a = [b for b in blocks if (b['tr'] & 0x7F) == atrack['track_no']]
    if not v or not a:
        raise SystemExit('error: no video or audio blocks found in the segment')
    return dict(data=data, T=T, header=header, fc=fc, tracks=tracks,
                encoders=encoders, v_dur=v_dur, a_dur=a_dur,
                n_dur=len(durations), blocks=blocks, cues=cues,
                noncluster=noncluster, v=v, a=a,
                vkey=vtrack['key'], akey=atrack['key'],
                vcodec=vtrack['codec'], acodec=atrack['codec'],
                acfg=atrack.get('acfg'))

def sps_from_stream(v, data, vkey, max_blocks=16):
    """SPS/PPS from the first decrypted video blocks, or (None, None)."""
    for b in v[:max_blocks]:
        try:
            nals = split_nals(avcc_to_annexb(
                decrypt_pkt(data, b['d'], b['dlen'], vkey)))
        except SystemExit:
            continue
        sps = next((x for x in nals if (x[0] & 0x1F) == 7), None)
        pps = next((x for x in nals if (x[0] & 0x1F) == 8), None)
        if sps is not None and pps is not None:
            return sps, pps
    return None, None

def expect_params(src):
    """Parameters derived from the header data: fps, sample rate,
    channel count, timescale and duration. The sample rate and the
    channel count come from the AAC config in the plaintext header;
    when it is absent they are estimated from the audio units."""
    N, na = len(src['v']), len(src['a'])
    fps_raw = N / src['v_dur']
    fps = snap_fps(fps_raw)
    VDUR = 512
    VSCALE = max(1, round((fps if fps is not None else fps_raw) * VDUR))
    if src['acfg']:
        rate, chan = src['acfg']
    else:
        rate, chan = snap_rate(round(na * 1024 / src['a_dur'])), None
    exp_dur = max(N * VDUR / VSCALE, na * 1024 / rate)
    return dict(N=N, na=na, fps_raw=fps_raw, fps=fps,
                VSCALE=VSCALE, rate=rate, chan=chan,
                exp_dur=exp_dur, VDUR=VDUR)

# ==================== command: probe ====================
def cmd_probe(path):
    src = load_source(path)
    data = src['data']
    print(f'probe: {os.path.basename(path)}   {len(data):,} B   md5 {hashlib.md5(data).hexdigest()}')
    print()

    pre, mdat_off = container_map(data)
    if mdat_off is None:
        raise SystemExit('error: mdat box not found')
    T = src['T']

    print('[container]')
    for off, typ, sz in pre:
        if typ is None:
            raw = data[off:off+8]
            if all(32 <= c < 127 for c in raw):
                name = "'" + raw.decode('latin-1').rstrip() + "'"
            else:
                name = repr(raw)
            print(f'  {name:<12}{sz:>12,} B   @ 0x{off:08x}   marker')
        else:
            name = typ.decode('latin-1').rstrip()
            if typ == b'ftyp':
                major, brands = ftyp_brands(data, off, sz)
                note = f'{major} ({", ".join(brands)})' if brands else (major or '')
            else:
                note = ''
            print(f'  {name:<12}{sz:>12,} B   @ 0x{off:08x}   {note}'.rstrip())
    szf = int.from_bytes(data[mdat_off:mdat_off+4], 'big')
    payload = len(data) - mdat_off - 8
    note = 'payload runs to EOF (size field truncated)' if szf < 8 else ''
    print(f'  {"mdat":<12}{payload:>12,} B   @ 0x{mdat_off + 8:08x}   {note}'.rstrip())
    print()

    print('[mdat payload]')
    print(f'  chunk table   8 B   @ 0x{mdat_off + 8:08x}')
    prev = analyze_stub(data, mdat_off, T)
    if prev:
        print(f'  fake stub     PRESENT   {prev["ln"]:,} B   @ 0x{prev["off"]:08x}')
    else:
        print('  fake stub     ABSENT')
    print(f'  EBML segment  {len(data) - T:,} B   @ 0x{T:08x}')
    print()

    print('[EBML header]')
    print(f'  header size   {len(src["header"])} B   clusters from 0x{src["fc"]:x}')
    if src['encoders']:
        print(f'  encoder       {src["encoders"][0]}')
    for i, t in enumerate(src['tracks'], 1):
        tn = t['track_no'] if t['track_no'] is not None else '?'
        print(f'  track {i}   {t["codec"]:<16}  key {t["key"].hex()}   (track no {tn})')
    print(f'  durations     video {src["v_dur"]:.3f} s   audio {src["a_dur"]:.3f} s')
    if src['n_dur'] > 2:
        print(f'  NOTE: {src["n_dur"]} durations in header, the first two are used')
    print()

    print('[blocks]')
    print(f'  total   {len(src["blocks"]):,}')
    print(f'  video   {len(src["v"]):,}')
    print(f'  audio   {len(src["a"]):,}')
    if src['cues']:
        print(f'  Cues @ 0x{src["cues"][0]:x} ({src["cues"][1]} B)')
    if src['noncluster']:
        print(f'  NOTE: {src["noncluster"]} non-cluster top-level elements skipped')
    print()

    print('[derived parameters]')
    sps_nal, pps_nal = sps_from_stream(src['v'], data, src['vkey'])
    sps_src = 'first decrypted video block'
    if sps_nal is None:
        h = sps_pps_from_header(src['header'])
        if h:
            sps_nal, pps_nal = h
            sps_src = 'plaintext segment header'
    if sps_nal is not None:
        try:
            sps = parse_sps(sps_nal[1:])
            prof = PROF.get(sps['prof'], str(sps['prof']))
            lvl = f'L{sps["lvl"] // 10}.{sps["lvl"] % 10}'
            print(f'  video   H.264 {prof} {lvl}   {sps["w"]}x{sps["h"]}   (SPS: {sps_src})')
        except Exception:
            print(f'  video   SPS found but not parseable ({sps_src})')
    else:
        print('  video   SPS not found')
    p = expect_params(src)
    fps_s = f'{p["fps_raw"]:.4f}' + (f' -> {p["fps"]}' if p['fps'] is not None else '')
    print(f'  fps     {fps_s}   ({p["N"]:,} frames / {src["v_dur"]:.3f} s)')
    if p['chan'] is not None:
        print(f'  audio   AAC-LC   {p["rate"]} Hz   {p["chan"]} ch '
              f'({"stereo" if p["chan"] == 2 else "mono"}) (header codec config)')
    else:
        aud = bytearray(); aal = []
        for b in src['a'][:64]:
            pt = decrypt_pkt(data, b['d'], b['dlen'], src['akey'])
            aud += pt
            aal.append(len(pt))
        chan = probe_channels(bytes(aud), aal, p['rate'], find_ffmpeg(),
                              os.path.dirname(os.path.abspath(path)))
        if chan is None:
            print(f'  audio   AAC-LC   {p["rate"]} Hz   channels not determined (probe failed, assume stereo)')
        else:
            print(f'  audio   AAC-LC   {p["rate"]} Hz   {chan} ch ({"stereo" if chan == 2 else "mono"}, first 64 AU)')
    v_dur = p['N'] * p['VDUR'] / p['VSCALE']
    a_dur = p['na'] * 1024 / p['rate']
    print(f'  duration  ~{max(v_dur, a_dur):.3f} s   (video {v_dur:.3f} s, audio {a_dur:.3f} s)')
    return 0

# ==================== command: decrypt ====================
def cmd_decrypt(inp, outp):
    src = load_source(inp)
    data, v, a = src['data'], src['v'], src['a']
    vkey, akey = src['vkey'], src['akey']
    N, na = len(v), len(a)
    print(f'decrypt: {os.path.basename(inp)} -> {os.path.basename(outp)}')
    print(f'  EBML segment @ 0x{src["T"]:x}   header {len(src["header"])} B   clusters from 0x{src["fc"]:x}')
    print(f'  video key   {vkey.hex()}   ({src["vcodec"]})')
    print(f'  audio key   {akey.hex()}   ({src["acodec"]})')
    print(f'  blocks: {N:,} video + {na:,} audio')
    if src['n_dur'] > 2:
        print(f'  NOTE: {src["n_dur"]} durations in header, the first two are used')

    print('  decrypting video...')
    video = bytearray()
    for b in v:
        video += avcc_to_annexb(decrypt_pkt(data, b['d'], b['dlen'], vkey))
    video = bytes(video)
    print('  decrypting audio...')
    aud = bytearray()
    aal = []
    for b in a:
        pt = decrypt_pkt(data, b['d'], b['dlen'], akey)
        aud += pt
        aal.append(len(pt))
    aud = bytes(aud)

    nals = split_nals(video)
    sps_nal = pps_nal = None
    sps_src = None
    if len(nals) >= 2 and nals[0][0] == 0x67 and nals[1][0] == 0x68:
        sps_nal, pps_nal = nals[0], nals[1]
        sps_src = 'first NALs of the decrypted stream'
    else:
        h = sps_pps_from_header(src['header'])
        if h:
            sps_nal, pps_nal = h
            sps_src = 'plaintext segment header'
    if sps_nal is None or pps_nal is None:
        raise SystemExit('error: SPS/PPS not found in the stream or the header')
    vcl = [x for x in nals if (x[0] & 0x1F) in (1, 5)]
    if len(vcl) != N:
        raise SystemExit(f'error: VCL NAL count {len(vcl)} != video block count {N}')

    sps = parse_sps(sps_nal[1:])
    width, height = sps['w'], sps['h']
    if sps['poc_type'] != 0 or not sps['fmo']:
        raise SystemExit('error: unsupported SPS (need poc_type=0, frame_mbs_only=1)')
    prof = PROF.get(sps['prof'], str(sps['prof']))
    print(f'  SPS: {prof} L{sps["lvl"] // 10}.{sps["lvl"] % 10} '
          f'{width}x{height}   (from {sps_src})')

    p = expect_params(src)
    if not (1 <= p['fps_raw'] <= 120):
        raise SystemExit(f'error: fps {p["fps_raw"]:.3f} out of the sane range')
    fps_s = f'{p["fps_raw"]:.4f}' + (f' -> {p["fps"]}' if p['fps'] is not None else '')
    print(f'  fps: {fps_s}   timescale {p["VSCALE"]} unit {p["VDUR"]}')
    print(f'  audio: {p["rate"]} Hz, {na:,} AU')
    if p['chan'] is not None:
        chan = p['chan']
        print(f'  channels: {chan} ({"stereo" if chan == 2 else "mono"}) (header codec config)')
    else:
        chan = probe_channels(aud, aal, p['rate'], find_ffmpeg(),
                              os.path.dirname(os.path.abspath(outp)))
        if chan is None:
            chan = 2
            print('  NOTE: channel probe failed, assuming stereo')
        else:
            print(f'  channels: {chan} ({"stereo" if chan == 2 else "mono"})')

    print('  parsing slices + POC...')
    poc = parse_slices_and_poc(nals, sps, p['VDUR'])
    n_idr = sum(poc['isidr'])
    print(f'  {poc["N"]} frames, {n_idr} IDR, {poc["gops"]} GOPs')

    vavcc_sizes = []
    for x in vcl:
        if (x[0] & 0x1F) == 5:
            vavcc_sizes.append(4 + len(sps_nal) + 4 + len(pps_nal) + 4 + len(x))
        else:
            vavcc_sizes.append(4 + len(x))

    print('  muxing MP4...')
    out = mp4_mux(sps_nal, pps_nal, vcl, vavcc_sizes, aud, aal, poc,
                  width, height, p['VSCALE'], p['VDUR'], p['rate'], chan)
    with open(outp, 'wb') as f:
        f.write(out)

    fo = 0
    while fo < len(out):
        sz = int.from_bytes(out[fo:fo+4], 'big')
        tp = out[fo+4:fo+8].decode('latin-1')
        print(f'    {tp}: {sz:,} B @ {fo}')
        fo += sz
    dur = max(poc['N'] * p['VDUR'] / p['VSCALE'], len(aal) * 1024 / p['rate'])
    print(f'  duration: {dur:.3f} s ({int(dur // 60)}:{int(dur % 60):02d})')
    print(f'  written {outp}: {len(out):,} B   md5 {hashlib.md5(out).hexdigest()}')
    return 0

# ==================== command: check ====================
def _expected_payload(src):
    """Expected mdat payload size of the recovered file, computed from
    the source blocks."""
    exp = sum(b['dlen'] for b in src['a'])
    n_idr = 0
    for b in src['v']:
        pt = decrypt_pkt(src['data'], b['d'], b['dlen'], src['vkey'])
        i = 0
        while i + 4 < len(pt):
            l = int.from_bytes(pt[i:i+4], 'big')
            if l < 1 or i + 4 + l > len(pt):
                break
            t = pt[i+4] & 0x1F
            if t in (1, 5):
                exp += 4 + l          # sample = u32 length + slice NAL
                if t == 5:
                    n_idr += 1
            i += 4 + l                # SPS/PPS/other NALs are not samples
    sps_nal, pps_nal = sps_from_stream(src['v'], src['data'], src['vkey'], max_blocks=1)
    if sps_nal is None:
        h = sps_pps_from_header(src['header'])
        sps_nal, pps_nal = h if h else (None, None)
    if sps_nal is not None and pps_nal is not None:
        exp += n_idr * (8 + len(sps_nal) + len(pps_nal))
    return exp, (sps_nal, pps_nal)

def _mdat_payload(out):
    o, n = 0, len(out)
    while o + 8 <= n:
        sz = int.from_bytes(out[o:o+4], 'big')
        if out[o+4:o+8] == b'mdat' and sz >= 8:
            return sz - 8
        o += sz if sz >= 8 else 8
    return None

def cmd_check(outp, srcpath):
    if not os.path.isfile(outp):
        raise SystemExit(f'error: file not found: {outp}')
    info = ffprobe_info(outp)
    vst = next((s for s in info['streams'] if s.get('codec_type') == 'video'), None)
    ast = next((s for s in info['streams'] if s.get('codec_type') == 'audio'), None)
    if not vst or not ast:
        print(f'error: {outp} does not contain a video and an audio stream')
        return 1

    got = dict(frames=int(vst.get('nb_read_frames', 0) or 0),
               vpack=int(vst.get('nb_read_packets', 0) or 0),
               apack=int(ast.get('nb_read_packets', 0) or 0),
               w=int(vst['width']), h=int(vst['height']),
               rate=int(ast['sample_rate']), ch=int(ast['channels']),
               dur=float(info.get('format', {}).get('duration', 0) or 0))

    if srcpath:
        print(f'check: {os.path.basename(outp)}   (source: {os.path.basename(srcpath)})')
    else:
        print(f'check: {os.path.basename(outp)}   (no source given, ffprobe only)')
    print()
    print(f'  video   {vst.get("codec_name")} {vst.get("profile") or ""} '
          f'{got["w"]}x{got["h"]}   frames {got["frames"]:,}')
    print(f'  audio   {ast.get("codec_name")} {ast.get("profile") or ""} '
          f'{got["rate"]} Hz {got["ch"]} ch   packets {got["apack"]:,}')
    print(f'  duration {got["dur"]:.3f} s')
    if not srcpath:
        print()
        print('  result: OK (ffprobe decoded the video fully)')
        return 0
    print()

    src = load_source(srcpath)
    p = expect_params(src)
    exp_payload, (sps_nal, pps_nal) = _expected_payload(src)
    exp_w = exp_h = None
    if sps_nal is not None:
        try:
            sp = parse_sps(sps_nal[1:])
            exp_w, exp_h = sp['w'], sp['h']
        except Exception:
            pass
    if p['chan'] is not None:
        exp_ch = p['chan']
    else:
        aud = bytearray(); aal = []
        for b in src['a'][:64]:
            pt = decrypt_pkt(src['data'], b['d'], b['dlen'], src['akey'])
            aud += pt
            aal.append(len(pt))
        exp_ch = probe_channels(bytes(aud), aal, p['rate'], find_ffmpeg(),
                                os.path.dirname(os.path.abspath(outp)))
        if exp_ch is None:
            exp_ch = 2

    out = open(outp, 'rb').read()
    got_payload = _mdat_payload(out)

    rows = [
        ('video frames', f'{got["frames"]:,}', f'{p["N"]:,}', got['frames'] == p['N']),
        ('video packets', f'{got["vpack"]:,}', f'{p["N"]:,}', got['vpack'] == p['N']),
        ('audio packets', f'{got["apack"]:,}', f'{p["na"]:,}', got['apack'] == p['na']),
    ]
    if exp_w is not None:
        rows.append(('size', f'{got["w"]}x{got["h"]}', f'{exp_w}x{exp_h}',
                     got['w'] == exp_w and got['h'] == exp_h))
    rows.append(('sample rate', f'{got["rate"]} Hz', f'{p["rate"]} Hz', got['rate'] == p['rate']))
    rows.append(('channels', f'{got["ch"]}', f'{exp_ch}', got['ch'] == exp_ch))
    rows.append(('duration', f'{got["dur"]:.3f} s', f'{p["exp_dur"]:.3f} s',
                 abs(got['dur'] - p['exp_dur']) < 0.1))
    if got_payload is not None:
        rows.append(('mdat payload', f'{got_payload:,} B', f'{exp_payload:,} B',
                     got_payload == exp_payload))

    ok_all = True
    for name, g, e, ok in rows:
        if not ok:
            ok_all = False
        print(f'  {name:<14} got {g:<14} expected {e:<14} {"OK" if ok else "MISMATCH"}')
    print()
    print(f'result: {"PASS" if ok_all else "FAIL"}')
    return 0 if ok_all else 1

# ==================== usage / main ====================
USAGE = """\
mxrecover.py - recovery of H.264+AAC video from an mxv-damaged file.

The mxv format is a fake-codec scam, not DRM or copy protection: when
a video is saved from a certain crapware video player, the player
encrypts the media with AES-128-ECB, so the file can be played by that
player only - the same trick as ransomware, which encrypts files and
demands money to unlock them. The keys are not hidden, they sit in
plaintext in the file, so the "protection" achieves nothing except
trapping the user. mxrecover reads the keys from the file and
restores the video. The only unencrypted part of the media is a
9-second fake stub.

Usage:
  mxrecover.py help
  mxrecover.py probe <input>
  mxrecover.py decrypt <input> <output.mp4>
  mxrecover.py check <output.mp4> [input]

Commands:
  probe    Inspect the source without full decryption: container layout,
           mdat payload, fake stub (present / absent), EBML header
           (encoder, tracks, keys, codec config, durations), block
           counts and derived parameters (resolution, fps, sample
           rate, channels, duration).
  decrypt  Decrypt every block and write a playable MP4 (moov first).
  check    Validate a recovered MP4 with a full ffprobe decode.
           With a source file given, compare frame counts, resolution,
           sample rate, channels, duration and payload size against the
           source.  Exit code: 0 = PASS, 1 = FAIL.

Requirements:
  python3 + cryptography   (apt install python3-cryptography)
  ffmpeg + ffprobe         (looked up in /usr/bin, then on PATH)
"""

def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ('help', '-h', '--help', '?'):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == 'probe':
        if len(rest) != 1:
            raise SystemExit('usage: mxrecover.py probe <input>')
        return cmd_probe(rest[0])
    if cmd == 'decrypt':
        if len(rest) != 2:
            raise SystemExit('usage: mxrecover.py decrypt <input> <output.mp4>')
        return cmd_decrypt(rest[0], rest[1])
    if cmd == 'check':
        if not (1 <= len(rest) <= 2):
            raise SystemExit('usage: mxrecover.py check <output.mp4> [input]')
        return cmd_check(rest[0], rest[1] if len(rest) == 2 else None)
    print(f'error: unknown command: {cmd}', file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2

if __name__ == '__main__':
    try:
        rc = main()
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
        rc = 0 if not e.code else 1
    sys.exit(rc if isinstance(rc, int) else 1)
