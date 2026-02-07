# History

This file is the lab notebook for reverse engineering the macOS Apple Music app ("Music.app") and related system frameworks.

The guiding constraints for this project:

- Static analysis only (no network traffic inspection).
- Capture results, hypotheses, and evidence as we go.
- Avoid committing large derived artifacts; store them under `out/` (gitignored) and summarize here.

## 2026-02-07

**Environment**

- Host OS: macOS 26.0 (25A354), Darwin 25.0.0, arm64
- Local time: 2026-02-07 16:02:07 EST

**Target binary**

- Path: `/System/Applications/Music.app/Contents/MacOS/Music`
- Type: Mach-O universal binary (x86_64, arm64e)
- Size: 69,563,248 bytes
- SHA256 (file contents): `307134cc101931a620f7ece81fb688cf0e80d3e03d9d5ced2c039cb540ec0dbd`
- Code signing highlights:
  - Identifier: `com.apple.Music`
  - Signed Time: Aug 6, 2025 at 2:16:21 AM
  - Flags include `library-validation` and `runtime`

**Linked frameworks (partial, from `otool -L`)**

Notable dependencies that look relevant to "store" requests and Apple Music metadata:

- `/System/Library/PrivateFrameworks/AppleMediaServices.framework/.../AppleMediaServices`
- `/System/Library/PrivateFrameworks/iTunesCloud.framework/.../iTunesCloud`
- `/System/Library/Frameworks/MusicKit.framework/.../MusicKit`
- `/System/Library/PrivateFrameworks/MusicKitInternal.framework/.../MusicKitInternal`
- `/System/Library/PrivateFrameworks/AMPDesktopUI.framework/.../AMPDesktopUI`
- `/System/Library/PrivateFrameworks/AMPLibrary.framework/.../AMPLibrary`

**First-pass string scan (lyrics-focused)**

I ran a quick `strings` filter pass looking for URL-ish text and Apple Music concepts like lyrics/storefront/adamId.

Observations:

- There appears to be a concrete "store lyrics" flow in the binary:
  - `StoreGetLyricsRequest`
  - `StoreLyrics`
  - `LyricsHandler`
  - `storefrontIdentifier`
  - `storeAdamID` / `storeSubscriptionAdamID`
  - `lyric-id`, `lyric-language`
- Lyrics parsing looks TTML-based (timed text markup):
  - `TSLLyricsSongInfo::CreateFromTTML`
  - `TSLLyricsLine`, `TSLLyricsWord`, `TSLLyricsTranslation`, etc.
- Hardcoded URL patterns surfaced (not obviously API endpoints yet):
  - `https://embed.music.apple.com`
  - `https://isq11.mzstatic.com/image/thumb/.../{w}x{h}bb.{f}`

**Hypotheses**

- `StoreGetLyricsRequest` likely makes a network request keyed by `(storefrontIdentifier, storeAdamID)` and receives TTML that `TSLLyrics*` parses into a timed-lyrics model.
- Translation support probably exists in the payload (or via a follow-up request) given `TSLLyricsTranslation*`.

**Next steps**

- Expand static scanning beyond the main `Music` binary into likely "API surface" frameworks (`AppleMediaServices`, `iTunesCloud`, `MusicKitInternal`, `AMPLibrary`) to find:
  - hostnames / base URLs
  - request path templates
  - JSON keys and response schemas
- Use Objective-C / Swift metadata dumps (`otool -ov`, `strings` focused on selectors) to locate request builders and parameter names around lyrics, albums, artists, and catalog lookup.

