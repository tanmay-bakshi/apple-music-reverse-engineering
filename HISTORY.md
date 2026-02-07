# History

This file is the lab notebook for reverse engineering the macOS Apple Music app ("Music.app") and related system frameworks.

The guiding constraints for this project:

- Static analysis only (no network traffic inspection).
- Capture results, hypotheses, and evidence as we go.
- Avoid committing large derived artifacts; store them under `out/` (gitignored) and summarize here.

## Logging conventions

This is meant to be "near real-time" notes. I will write down what I tried, what I expected, what I observed, and what I’m thinking next, even when it turns out to be a dead end.

- Times are local machine time (EST) unless explicitly stated otherwise.
- I’ll often include abbreviated command invocations and small output excerpts (not full dumps).

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

### Timeline notes

#### 2026-02-07 16:00-16:03

Bootstrapped the repository and immediately started by "fingerprinting" the main binary so we can keep results reproducible across OS updates.

What I did:

- Located Music.app on disk via Spotlight metadata: `mdfind "kMDItemCFBundleIdentifier == 'com.apple.Music'"`
- Captured baseline metadata:
  - `file` (architecture)
  - `stat` (size)
  - `shasum -a 256` (content hash)
  - `codesign -dv --verbose=4` (signing flags, signing time)
  - `otool -L` (linked dylibs)

My expectation:

- The main binary would likely contain at least *some* obvious service endpoints (hosts, base URLs) as plain strings.

What I observed:

- The binary surfaces plenty of "domain language" around lyrics, storefronts, and adamIds, but (so far) not an obvious "Apple Music API base URL" beyond things like `https://embed.music.apple.com` and an `mzstatic` image URL template.

Where I want to go next:

- Look for endpoints in other Mach-O components in the app bundle (plug-ins, XPC services, extensions).
- If those still don’t show endpoints, pivot to analyzing system/private frameworks where request builders often live.

#### 2026-02-07 16:03-16:05

I enumerated other Mach-O binaries inside Music.app:

- `/System/Applications/Music.app/Contents/PlugIns/com.apple.Music.web.bundle/Contents/MacOS/com.apple.Music.web`
- `/System/Applications/Music.app/Contents/PlugIns/MusicCacheExtension.appex/Contents/MacOS/MusicCacheExtension`
- `/System/Applications/Music.app/Contents/PlugIns/MusicStorageExtension.appex/Contents/MacOS/MusicStorageExtension`
- `/System/Applications/Music.app/Contents/XPCServices/VisualizerService.xpc/Contents/MacOS/VisualizerService`

What I did:

- Ran `strings` scans on those binaries and filtered for URL-ish / Apple Music-ish patterns.

What I observed:

- Nothing useful surfaced from those scans (at least not as plain strings with the patterns I used). This suggests:
  - endpoints are not stored as simple strings in those components, or
  - they’re constructed dynamically, or
  - they live in system/private frameworks rather than app bundle binaries, or
  - they live in web resources rather than the bundle’s Mach-O.

Immediate next idea:

- Inspect the *resources* for `com.apple.Music.web.bundle` (JS/HTML often contains concrete endpoints even if the Mach-O doesn’t).

#### 2026-02-07 16:05-16:10

Pivoted to likely "API surface" system/private frameworks referenced by `otool -L`:

- `AppleMediaServices.framework`
- `iTunesCloud.framework`
- `MusicKitInternal.framework`
- `AMPLibrary.framework`

What I expected:

- I’d be able to run `strings` on the framework binaries directly from `/System/Library/PrivateFrameworks/.../<FrameworkName>`.

What I observed:

- On this macOS version, these frameworks appear to be present mostly as directory structures with `Resources/` and code signatures, but *no on-disk Mach-O binary* at the expected `Versions/A/<name>` paths.
- Example: `AppleMediaServices.framework/Versions/A/` contains `Resources/` and `_CodeSignature/` only.

Hypothesis:

- This is consistent with Apple shipping many system/private frameworks inside the dyld shared cache: the file paths are "logical" install names, but the actual image bytes are embedded in `/System/Library/dyld/dyld_shared_cache_*`.

Next steps:

- Use `dyld_shared_cache_util` (or similar) to confirm that these images exist in the shared cache and extract *only the relevant images* for analysis (avoid multi-GB full extractions).
- In parallel, inspect the web bundle resources for hard-coded endpoints and request templates.

### Next steps (near term)

- Expand static scanning beyond the main `Music` binary into likely "API surface" frameworks (`AppleMediaServices`, `iTunesCloud`, `MusicKitInternal`, `AMPLibrary`) to find:
  - hostnames / base URLs
  - request path templates
  - JSON keys and response schemas
- Use Objective-C / Swift metadata dumps (`otool -ov`, `strings` focused on selectors) to locate request builders and parameter names around lyrics, albums, artists, and catalog lookup.
