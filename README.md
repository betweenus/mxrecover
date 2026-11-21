# mxrecover

Recovery of H.264 + AAC video from an mxv-damaged file.

An `mxv` file is a **fake-codec scam**: on the surface it looks like an
ordinary MP4 (ftyp, an `mxv ` marker, moov, free, mdat), but the real
media data is not stored in the MP4 boxes. It is kept in an
AES-128-ECB-encrypted EBML segment appended inside the mdat payload -
only the segment header (codec ids, per-track encryption keys,
codec configs, durations) and the 9-second fake stub are readable
without the keys.
Files of this kind are produced when a video is saved from a certain
crapware video player.

This is not DRM or copy protection. The player encrypts the videos the
user saves, so the resulting files can be played by that player only:
the user's own content is held hostage by the software, the same
behavior as ransomware, which encrypts files and then demands money to
restore them. The "protection" is not even real - the keys are stored
in plaintext in the file - it is a pure scam whose only purpose is to
damage the user's files and push them to keep using the player. The
player also inserts a 9-second fake stub, the only part of the media
left unencrypted. `mxrecover` undoes the damage.

`mxrecover` reads every key and parameter from the file itself, decrypts
the blocks, restores the H.264 parameter sets and the frame order, and
writes a standard playable MP4 (moov first).

## Commands

```
mxrecover.py help
mxrecover.py probe <input>
mxrecover.py decrypt <input> <output.mp4>
mxrecover.py check <output.mp4> [input]
```

- **`probe <input>`** - inspect a source without full decryption:
  container layout, mdat payload (chunk table, fake stub
  present/absent, EBML segment), header (encoder, tracks, keys,
  codec config, durations), block counts and derived parameters
  (resolution, fps, sample rate, channels, duration). The sample rate
  and the channel count come from the AAC config in the plaintext
  header; when it is absent the first audio units are decoded to
  detect the channel count. Only a few first blocks are decrypted,
  so it runs quickly.
- **`decrypt <input> <output.mp4>`** - full recovery: decrypts every
  block and muxes a valid MP4.
- **`check <output.mp4> [input]`** - validates a recovered MP4 with a
  full ffprobe decode. Without `input` it prints the stream information
  only; with a source file it compares frame counts, resolution, sample
  rate, channels, duration and the mdat payload size against the
  source. Exit code: `0` = PASS, `1` = FAIL.

## Requirements

- Python 3.8+ and the `cryptography` package
- `ffmpeg` and `ffprobe` - looked up in `/usr/bin`, then on `PATH`.
  Used for the audio channel fallback probe (when the plaintext
  header carries no AAC codec config) and for `check`.

Setup in a virtual environment:

```console
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

On Debian/Ubuntu install `python3-venv` first if `venv` is missing,
or skip the virtual environment and use the system package:
`sudo apt install python3-cryptography`.

## Example

```console
$ ./mxrecover.py probe mxsaved.mp4
$ ./mxrecover.py decrypt mxsaved.mp4 recovered.mp4
$ ./mxrecover.py check recovered.mp4 mxsaved.mp4
```
