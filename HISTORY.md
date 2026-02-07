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

#### 2026-02-07 16:10-16:13

I got unstuck on the “framework binaries aren’t on disk” issue by realizing two things:

1. On this OS, dyld shared caches live under the cryptex path, not at `/System/Library/dyld/`.
2. `/usr/bin/dyld_info` can read images directly out of the dyld shared cache using their install-name path, even when the corresponding file does not exist on disk.

Concrete checks:

- Found caches at:
  - `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e` (plus `.01` and `.map`/`.atlas`)
- Verified `dyld_info` can open cache images by install name:
  - `dyld_info -platform /System/Library/PrivateFrameworks/iTunesCloud.framework/Versions/A/iTunesCloud`

This is a huge unlock because it gives me a way to “strings” scan frameworks without needing external extraction tools.

##### First big endpoint discovery: `amp-api.music.apple.com`

I dumped the `__TEXT,__cstring` section for iTunesCloud and immediately saw a concrete AMP API endpoint:

- `https://amp-api.music.apple.com/v1/me/account?include=social-profile&with=nonOnboarded`

Also saw other related host strings and patterns in iTunesCloud:

- `amp-api.music.apple.com`
- `amp-api-edge.music.apple.com`
- `https://init.itunes.apple.com/bag.xml`
- Regex patterns matching catalog endpoints:
  - `.*/v1/catalog/([A-Za-z]+)/albums.*`
  - `.*/v1/catalog/([A-Za-z]+)/songs.*`
  - `.*/v1/catalog/([A-Za-z]+)/artists.*`
  - `.*/v1/catalog/([A-Za-z]+)/search/suggestions.*`
  - `.*/v1/(catalog|social)/([A-Za-z]+)/search.*`

Immediate interpretation:

- iTunesCloud “knows about” `/v1/catalog/{storefront}/...` and can identify those URLs.
- The main “Apple Music” API host appears to be `amp-api.music.apple.com` (at least for some endpoints).

##### MusicKitInternal likely builds URLs dynamically

MusicKitInternal’s `__TEXT,__cstring` contains the hostnames:

- `amp-api.music.apple.com`
- `amp-api-carry.music.apple.com`

But I didn’t see obvious `/v1/...` path literals in that same section. However, I did see lots of resource-type strings (`albums`, `artists`, `songs`, `library-*`, etc.) and file-path strings such as `MusicCatalogResourceRequest+Internal.swift`, which strongly suggests URL paths are built from smaller pieces.

##### Bag keys for lyrics in the main Music binary

I re-ran a more aggressive `strings` scan on the main `Music` binary and found two especially important bag keys:

- `bag://musicSubscription/ttmlLyrics`
- `bag://musicSubscription/lyrics`

And a bag bootstrap URL:

- `https://init.itunes.apple.com/bag.xml?ix=6`

This suggests the lyrics endpoint(s) and likely request path templates are *not* hard-coded, but delivered via the bag configuration and resolved at runtime.

#### 2026-02-07 16:13-16:20

At this point I decided to lean harder into two parallel threads:

1. Framework-driven “hard-coded” endpoints and patterns (via `dyld_info`).
2. Bag-driven “configuration keys” embedded in the Music binary.

##### More detail on iTunesCloud’s AMP API knowledge

From `dyld_info -section __TEXT __cstring /System/Library/PrivateFrameworks/iTunesCloud.framework/Versions/A/iTunesCloud`:

- Concrete endpoints:
  - `https://amp-api.music.apple.com/v1/me/account?include=social-profile&with=nonOnboarded`
  - `https://amp-api.music.apple.com/v1/me/social/profile?include=social-profile&with=nonOnboarded`
- Hostnames:
  - `amp-api.music.apple.com`
  - `amp-api-edge.music.apple.com`
- URL classification regexes:
  - `.*/v1/catalog/([A-Za-z]+)/albums.*`
  - `.*/v1/catalog/([A-Za-z]+)/songs.*`
  - `.*/v1/catalog/([A-Za-z]+)/artists.*`
  - `.*/v1/me/library/search.*`

This is useful for two reasons:

- It corroborates that `/v1/catalog/{storefront}/...` is a real on-the-wire path shape.
- It tells me the app/framework ecosystem treats “catalog”, “social”, and “me/library/search” as first-class endpoint families.

##### Bag keys in the Music binary (beyond lyrics)

I broadened the scan in the main Music binary and found a lot of `bag://...` keys, which look like late-bound configuration for “where to talk to which service”.

A few that immediately look relevant to Apple Music APIs:

- `bag://contentPlay/base-url`
- `bag://sf-api-token-service-url`
- `bag://radio/fetchMetadata-url`
- `bag://storeplatform-lookup-url`
- `bag://storeplatform-lookup-url-unpersonalized`
- `bag://musicCommon/userProfile`
- `bag://musicCommon/reportConcern/url`

I also noticed the binary directly includes `amp-api.videos.apple.com` (suggesting a sibling AMP API host used for video catalog/playback metadata).

##### Lyrics: multiple “tracks” for fetching

For lyrics specifically, the binary contains *both* bag keys and separate “cloud-lyrics” strings:

- Bag keys:
  - `bag://musicSubscription/ttmlLyrics`
  - `bag://musicSubscription/lyrics`
- Other (non-bag) keys/labels:
  - `cloud-lyrics-info`
  - `cloud-lyrics-token`
  - `cloud-lyrics`

Near `cloud-lyrics-info`, I saw a URL format string:

- `%S://%S:%u%S/databases/%u/extra_data/%@`

This *smells like* a DAAP-ish path shape (database/extra_data) where the scheme/host/port are variable. I don’t yet know if this is used for:

- local-network sharing (iTunes-style), or
- a store/cloud backend that happens to reuse a “database/extra_data” abstraction, or
- an internal protocol wrapper that still uses HTTP(s) but with this path shape.

Next idea:

- Find where `cloud-lyrics-*` and `musicSubscription/*Lyrics` are referenced in code (selectors, symbol names), to identify the request builder and the “final URL shape” before it’s sent.

##### Quick dead-end: `com.apple.Music.web.bundle` has no web assets

I initially assumed the “web” plug-in would contain JavaScript/HTML with concrete endpoints. But on disk, this bundle appears to contain only:

- `Contents/Info.plist`
- `Contents/version.plist`
- `Contents/MacOS/com.apple.Music.web` (Mach-O bundle)

No `.js`, `.html`, `.json` resources were present under `Contents/` (at least at shallow depth). So if Music is using a web surface, it’s likely loading remote content or using another packaging mechanism.

##### Header + auth scheme evidence (developer token + music user token)

Two frameworks/binaries surfaced very explicit evidence of the “Apple Music API style” auth shape:

- In iTunesCloud:
  - Header names: `Authorization`, `Music-User-Token`
  - Header format string: `Bearer %@`
  - ObjC selector / ivar metadata references to:
    - `ICDeveloperTokenProvider`
    - `_developerToken`
    - `ICMusicUserTokenCache`
    - `_buildMusicKitURLRequestWithBaseURLRequest:completionHandler:`
    - `_buildUserTokenBasedMusicKitURLRequestWithBaseURLRequest:developerToken:completionHandler:`
- In AppleMediaServices:
  - Many Apple request headers as constants, including:
    - `X-Apple-Store-Front` / `X-Set-Apple-Store-Front`
    - `X-Apple-Client-Id`, `X-Apple-Client-Versions`, etc.

This tightens the mental model:

- There is a “developer token” concept (likely the Bearer token) and a separate “music user token”.
- Requests are storefront-aware (storefront header exists and there is lots of machinery around storefront suffixes/combining).

##### Tooling: deterministic bag key extraction

Because I keep coming back to `bag://...` keys as “what services exist” and “what URLs are late-bound”, I wrote a tiny helper script:

- `scripts/extract_bag_keys.py`

It runs `/usr/bin/strings` and extracts all `bag://...` occurrences, producing a unique sorted list and optional grouping.

First run against `/System/Applications/Music.app/Contents/MacOS/Music`:

- Found 47 unique `bag://...` keys.
- A few that seem directly relevant to Apple Music API surface area:
  - `bag://musicSubscription/lyrics`
  - `bag://musicSubscription/ttmlLyrics`
  - `bag://sf-api-token-service-url`
  - `bag://contentPlay/base-url`
  - `bag://radio/fetchMetadata-url`
  - `bag://storeplatform-lookup-url`
  - `bag://musicCommon/userProfile`

### Next steps (near term)

- Expand static scanning beyond the main `Music` binary into likely "API surface" frameworks (`AppleMediaServices`, `iTunesCloud`, `MusicKitInternal`, `AMPLibrary`) to find:
  - hostnames / base URLs
  - request path templates
  - JSON keys and response schemas
- Use Objective-C / Swift metadata dumps (`otool -ov`, `strings` focused on selectors) to locate request builders and parameter names around lyrics, albums, artists, and catalog lookup.

#### 2026-02-07 17:18-

Picking back up with the explicit goal: **follow the lyrics pipeline far enough to identify the request construction + response parsing path**.

Context recap (from earlier work):

- `Music` contains bag keys:
  - `bag://musicSubscription/ttmlLyrics`
  - `bag://musicSubscription/lyrics`
- There are also non-bag strings:
  - `cloud-lyrics-info`, `cloud-lyrics-token`, `cloud-lyrics`
- There is a timed-metadata ingestion path in the player that *looks like* it could drive lyric-related state.

I found that `out/` already contains LLDB disassemblies that were produced earlier:

- `out/unnamed_14523.s` (LLDB: `Music` arm64e, `___lldb_unnamed_symbol14523` at `0x10024C628`)
- `out/unnamed_32280.s` (LLDB: `Music` arm64e, `___lldb_unnamed_symbol32280` at `0x10057AC9C`)

The next immediate step is to decode a C++ vtable that shows up in `___lldb_unnamed_symbol14523`.

Why this matters:

- In `___lldb_unnamed_symbol14523` the code allocates a 0x68-byte object and manually writes a signed vptr.
- Later it calls a virtual method via vtable lookup (`blraa`) at an offset like `0x78`.
- If we can recover the *actual target addresses* of the vtable entries, we can disassemble those functions and look for:
  - references to `bag://musicSubscription/*Lyrics`
  - references to `cloud-lyrics-*`
  - TTML parsing (`CreateFromTTML`-style)
  - URL/request building logic

Key detail: on arm64e these vtable pointers are not plain pointers on disk (they are dyld chained-fixup encodings), so I need `dyld_info -fixup_chain_details` to read the true rebase targets.

#### 2026-02-07 17:18-17:25

First concrete progress: I generated a full fixup dump for the `Music` arm64e slice:

- `out/dyld_fixup_chain_details_arm64e.txt` (34MB)

Then I searched for the vtable “address point” I saw being constructed in `___lldb_unnamed_symbol14523`.

From `___lldb_unnamed_symbol14523` (see `out/unnamed_14523.s`), the vptr is computed as:

- `adrp x16, 6974; add x16, x16, #0x198; add x16, x16, #0x10`
- This yields an address point at `0x101D8A1A8` in `Music.__DATA_CONST.__const`.
- VM offset form: `0x01D8A1A8` (since base `0x100000000`)

Looking at `dyld_info -fixup_chain_details`, the bytes at `0x01D8A1A8` are not a literal pointer; it’s an `auth-rebase` fixup.

The vtable entries at and after `0x01D8A1A8` look like:

- `0x01D8A1A8`: `auth-rebase target 0x00000747B20`  -> function `0x100747B20`
- `0x01D8A1B0`: `auth-rebase target 0x0000024C85C`  -> function `0x10024C85C`
- `0x01D8A1B8`: `auth-rebase target 0x0000024C860`  -> function `0x10024C860`
- `0x01D8A1C0`: `auth-rebase target 0x000004BA544`  -> function `0x1004BA544`
- ... (more entries)
- `0x01D8A220`: `auth-rebase target 0x0000024C788`  -> function `0x10024C788`

This is already useful because `0x10024C788` is exactly the start of `___lldb_unnamed_symbol14524` (which LLDB printed immediately after `___lldb_unnamed_symbol14523`).

So now I can map the “virtual call at vtable offset 0x78” from `___lldb_unnamed_symbol14523` to a concrete implementation:

- vtable offset `0x78` -> entry address `0x01D8A220` -> target `0x10024C788` -> `___lldb_unnamed_symbol14524`

Next: correlate this with the timed metadata handler.

I also generated a disassembly for the timed-metadata entrypoint by address:

- `out/itmpavitem_timedmetadata_addr.s` (LLDB disassembly starting at `0x10039F484`)

In that disassembly I can now see the exact vtable slot used when processing parsed timed metadata:

- It calls the parser: `bl 0x10057AC9C` (`___lldb_unnamed_symbol32280`).
- Then it does vtable dispatch via:
  - `ldr x8, [x16, #0x18]!` then `blraa x8, x17` with `movk x17, #0x592c, lsl #48`.

That `0x592c` constant matches the `diversity: 0x592C` shown in the fixup-chain detail line for vtable entry `0x01D8A1C0`, which strongly confirms:

- the timed-metadata path is calling the vtable function at offset `0x18`
- the target implementation for that slot is at `0x1004BA544`

So the next immediate disassembly target is `0x1004BA544`.

#### 2026-02-07 17:25-

User reminder: keep `HISTORY.md` close to “live logging”. I’m going to start pasting the exact commands + the specific snippets they unlocked.

First, I did a broad string scan to see if the binary contains any *named* lyrics classes (instead of only generic bag keys):

```sh
strings -a /System/Applications/Music.app/Contents/MacOS/Music | rg -i "ttml|lyric" | head -n 80
```

This immediately surfaced a dedicated lyrics stack inside the `Music` binary:

- `StoreGetLyricsRequest`
- `LyricsHandler` with method `StartGettingStoreLyrics`
- `StoreLyrics`
- `LyricsTagParser`
- TTML parsing types: `TSLLyricsSongInfo`, `TSLLyricsSection`, `TSLLyricsLine`, etc.

This is the first time I’m seeing a *directly named request type* for lyrics (as opposed to only the bag keys).

Next step: resolve these symbols to concrete addresses (via `nm` / `lldb image lookup`), then disassemble around `StoreGetLyricsRequest` and follow where it resolves `bag://musicSubscription/lyrics` or `bag://musicSubscription/ttmlLyrics`.

#### 2026-02-07 17:27-17:32

More concrete lyric-specific anchors.

I asked dyld_info for the *addresses* of the lyrics bag keys inside `Music`’s `__TEXT,__cstring`:

```sh
dyld_info -arch arm64e -section __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music \
  | rg -n "bag://musicSubscription/(ttmlLyrics|lyrics)" | head
```

Result:

- `0x101A3351F` `"bag://musicSubscription/ttmlLyrics"`
- `0x101A3353E` `"bag://musicSubscription/lyrics"`

Then I checked for a request/op name string that looks analogous to the timed-metadata fetch path (which uses `"StoreFetchTimedMetadataBlobInfo"`).

```sh
dyld_info -arch arm64e -section __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music \
  | rg -n '"StoreGetLyrics"' | head
```

Result:

- `0x101A3354D` `"StoreGetLyrics"`

So we have a plausible triad:

- `StoreGetLyrics` (operation name)
- `bag://musicSubscription/lyrics`
- `bag://musicSubscription/ttmlLyrics`

Also, I checked `__oslogstring` for lyric-specific logging I can use as additional anchors:

```sh
dyld_info -arch arm64e -section __TEXT __oslogstring /System/Applications/Music.app/Contents/MacOS/Music \
  | rg -i "lyric" | head -n 20
```

Interesting log strings include:

- `RemoteAssetDownloadManager::SetDownloadedTrackLyrics: ...`
- `Retrieved lyrics for %u tracks ...`
- `TrackProcessor::CopyTrackLyricsData: ...`
- `timed_lyric_animate`

Next step: find the *code* that references the addresses above.

My current hunch is that `StoreGetLyrics` is implemented via the same StoreRequest/vtable machinery as the timed-metadata code path (`StoreFetchTimedMetadataBlobInfo`). In that path I found tiny helper functions that look like:

- load bag key string -> jump to a generic helper
- load op name string -> jump to a generic helper

If that pattern repeats, there should be small functions in `__TEXT,__text` that reference:

- `"StoreGetLyrics"` and/or
- `"bag://musicSubscription/lyrics"`

To locate those without a GUI disassembler, I may need to build a small script that scans arm64e `__TEXT,__text` for `adrp/add` sequences that materialize a given target address.

(Also noted for later tooling:)

```sh
lipo -detailed_info /System/Applications/Music.app/Contents/MacOS/Music | head -n 40
```

This confirms the universal binary layout:

- x86_64 slice: offset `16384`, size `34797568`
- arm64e slice: offset `34816000`, size `34747248`

#### 2026-02-07 17:35-18:15: StoreGetLyrics Plumbing Found (Catch-Up)

I ended the previous section with "I may need to build a script that scans `__TEXT,__text` for `adrp/add` pairs". I did that, and it was the key that unlocked most of the lyrics pipeline.

Repo state snapshot (before continuing):

```sh
cd /Users/tanmaybakshi/apple-music-reverse-engineering
git status --porcelain=v1
git log -n 5 --oneline --decorate
```

At this point:

- `HISTORY.md` is modified.
- Two new (untracked) scripts exist:
  - `scripts/find_arm64_adrp_add_xrefs.py`
  - `scripts/find_arm64_bl_xrefs.py`

##### Tooling: ADRP+ADD xref finder

I created `scripts/find_arm64_adrp_add_xrefs.py` to scan the arm64/arm64e `__TEXT,__text` section for `adrp`+`add` sequences that materialize a *specific* VM address.

This is useful because, even in stripped code, references to cstrings or oslog strings often look like:

```
adrp xN, <page>
add  xN, xN, <page_off>
```

##### Important gotcha: dyld_info cstring addresses are NOT the string start

This took me a while to realize and is worth writing down clearly:

- `dyld_info -section __TEXT __cstring ...` prints the **address of the NUL terminator**, not the address of the first character.
- To get the string start: `start_addr = dyld_addr - len(string)`.

I verified this directly by comparing dyld_info vs otool for `StoreGetLyrics`:

```sh
dyld_info -arch arm64e -section __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music \
  | rg -n '\"StoreGetLyrics\"' | head -n 1
```

dyld_info shows:

- `0x101A3354D` `"StoreGetLyrics"`

Then:

```sh
otool -arch arm64e -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music \
  | rg -n "StoreGetLyrics" | head -n 1
```

otool shows:

- `0000000101a3353f  StoreGetLyrics`

Length of `"StoreGetLyrics"` is 14 bytes, and `0x101A3353F + 0xE = 0x101A3354D`. So dyld_info is giving the NUL address.

This also explains why my earliest xref attempts looked "off-by-one-ish" and why xrefs sometimes landed one instruction away from what I expected.

##### StoreGetLyrics: key cstring anchors (VM addrs)

I used dyld_info/otool to locate the major lyric keys:

- Response keys:
  - `"ttml"` at dyld_info NUL `0x101A334F3`, start `0x101A334EF`
  - `"lyricsId"` at dyld_info NUL `0x101A334FC`, start `0x101A334F4`
- Bag keys / op name:
  - `"bag://musicSubscription/ttmlLyrics"` NUL `0x101A3351F`, start `0x101A334FD`
  - `"bag://musicSubscription/lyrics"` NUL `0x101A3353E`, start `0x101A33520`
  - `"StoreGetLyrics"` NUL `0x101A3354D`, start `0x101A3353F`

With the ADRP+ADD scanner, I searched for xrefs to those start addrs and found a tight block of functions in `__TEXT,__text` around `0x100809000` that looked like a StoreRequest subclass.

##### StoreGetLyricsRequest: main functions (arm64e)

I disassembled the discovered functions with LLDB and wrote the results into `out/`:

- `out/dis_100809000.s`: includes request ctor + param builder
- `out/dis_44397_full.s`: full response parser disassembly
- `out/dis_lyrics_xrefs_block.s`: helper block around the same region

The key methods (arm64e VM addresses):

- `0x100809000` `___lldb_unnamed_symbol44392`
  - Looks like a ctor/init: calls base ctor, then writes:
    - `[this+0x170] = x1` (the ID passed in)
    - `[this+0x178] = w2` (flags)
  - Also stores a vptr (signed pointer) at `[this+0x0]`.
- `0x10080906C` `___lldb_unnamed_symbol44395`
  - Builds request parameters dictionary/array:
    - Always sets `"id"` to `[this+0x170]`
    - Sets `"itre"` to either 0 or 1 depending on bit0 of `[this+0x178]`:
      - `tbnz w8, #0x0, ...` then stores `1`
      - else stores `0`
    - Conditionally adds an additional param keyed by the cstring `"'l'"` if a value exists (cbz check on a pointer loaded from stack).
  - I have no clue what `"'l'"` means yet. It might actually be a quoted single-letter key used in the server API.
- `0x100809304` `___lldb_unnamed_symbol44397`
  - Parses the StoreGetLyrics response dictionary and writes into an out-struct (sret):
    - Out struct layout:
      - `out+0x0`: 16-byte refcounted value object (lyrics/ttml payload)
      - `out+0x10`: 1-byte flag (is_ttml)
      - `out+0x18`: 16-byte refcounted value object (id)
    - Semantics (inferred from key lookups + emptiness checks):
      1) Initialize `out+0x10` to 0.
      2) Look up `"ttml"`; move into `out+0x0`.
      3) If `out+0x0` is empty, fall back to `"lyrics"` into `out+0x0`.
      4) If `"ttml"` was non-empty, set `out+0x10 = 1`.
      5) Look up `"id"` into `out+0x18`.
      6) If `out+0x18` is empty, fall back to `"lyricsId"` into `out+0x18`.
- `0x100809754` `___lldb_unnamed_symbol44399`
  - Chooses the bag key string to use:
    - If bit `0x2` in `[this+0x178]` is set: returns `"bag://musicSubscription/ttmlLyrics"`
    - Else: returns `"bag://musicSubscription/lyrics"`
- `0x100809778` `___lldb_unnamed_symbol44400`
  - Returns `"StoreGetLyrics"` (the operation name).

I also reverse-identified two generic helpers used by the response parser:

- `0x1007483b0` `___lldb_unnamed_symbol39796`
  - Move-assign for the 16-byte refcounted value object: releases old, moves new, zeroes source.
- `0x1007488e0` `___lldb_unnamed_symbol39808`
  - Emptiness check for that value object:
    - Returns `1` if empty/null
    - Returns `0` if non-empty

##### StoreGetLyricsRequest vtable mapping (dyld fixup chain)

Because the binary is pointer-authenticated and stripped, I needed to prove these functions are actually *the* `StoreGetLyricsRequest` vtable entries (and not random code that happens to reference the same strings).

I used `dyld_info -fixup_chain_details` to locate the vtable addresspoint used in the ctor:

- The ctor at `0x100809000` loads a signed vptr from an `adrp/add` materialization that resolves to vtable addresspoint `0x101DD6CA0`.

Then, by scanning the fixup-chain output (`out/dyld_fixup_chain_details_arm64e.txt`), I found vtable entries pointing exactly at my tiny helpers:

- vtable entry -> `0x00000809754` (bag key selector `44399`)
- vtable entry -> `0x00000809778` (op name `44400`)
- vtable entry -> `0x0000080906C` (param builder `44395`)
- destructor-ish entries:
  - `0x00000809040` and `0x00000809044`

Finally, I found the RTTI-style name string for the type:

- `"21StoreGetLyricsRequest"` in `__TEXT,__const` at VM `0x1018E4175`

So I'm confident the block above is the real StoreRequest subclass for lyrics.

##### Store request HAR logging preference (static anchor)

While looking for other store-request machinery, I found a preference key:

- `"log-request-to-har-path"`

and a log string:

- `"Pref 'log-request-to-har-path' is not present or empty."`

I disassembled the referencing function at `0x100806D70` into:

- `out/dis_100806D70.s`

This looks like it conditionally writes requests out as HAR, which might be extremely useful later (but I'm staying purely static for now).

##### RemoteAssetDownloadManager: lyrics insertion path (static anchor)

From `__oslogstring` I previously saw:

- `Retrieved lyrics for %u tracks out of %d (and set lyrics for %u of those %u)`

I computed its start VM address (using the dyld_info NUL-terminator rule), then ran the ADRP+ADD xref scanner and found a callsite at:

- `0x10145852C`

Disassembling around that site led me to:

- `0x10145811C` `___lldb_unnamed_symbol97647`
  - `out/dis_10145811C.s`

This function is heavy, but the early portion strongly suggests it iterates a batch of track results and inserts lyrics, logging errors like:

- `"RemoteAssetDownloadManager::SetDownloadedTrackLyrics: HTTPError: %d"`
- `"RemoteAssetDownloadManager::SetDownloadedTrackLyrics: track lyrics insertion error: %d"`

So, very roughly:

`StoreGetLyrics` fetch -> some batching layer -> `RemoteAssetDownloadManager` insertion.

The missing link is: where does StoreGetLyricsRequest get created and how does its output get forwarded here?

##### Tooling: BL xref finder (to find callsites)

To answer the "missing link" question above, I added another static helper:

- `scripts/find_arm64_bl_xrefs.py`

It scans `__TEXT,__text` for `bl` instructions that resolve to a specific target VM address, so I can find callsites to:

- `StoreGetLyricsRequest` ctor `0x100809000`
- param builder `0x10080906C`
- response parser `0x100809304`

Next step: run the BL scanner against those addresses, then disassemble the surrounding functions to map:

- Who sets `[this+0x178]` flags (bit0 + bit1 meaning).
- Where responses are parsed and handed off (TTML parse vs plain lyrics).
