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

#### 2026-02-07 18:16-: Trying To Link StoreGetLyrics Into Callers

First I tried the new BL-xref tool directly on the most interesting StoreGetLyricsRequest helpers:

```sh
python3 scripts/find_arm64_bl_xrefs.py --target 0x100809000 | tee out/bl_xrefs_100809000.txt
python3 scripts/find_arm64_bl_xrefs.py --target 0x10080906C | tee out/bl_xrefs_10080906C.txt
python3 scripts/find_arm64_bl_xrefs.py --target 0x100809304 | tee out/bl_xrefs_100809304.txt
```

Results:

- ctor `0x100809000`: `xrefs=0`
- param builder `0x10080906C`: `xrefs=0`
- response parser `0x100809304`: `xrefs=1`
  - callsite: `0x100809A40`

So the ctor/param builder are likely invoked via:

- inlining (no direct call), and/or
- vtable dispatch (PAC-ed `blraa`), and/or
- indirect function pointer calls (`blr`/`blraa`) instead of immediate `bl`.

I disassembled the one parser callsite.

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1008099F0 -c 220 -b -r" \
  -o quit > out/dis_1008099F0.s 2> out/dis_1008099F0.err
```

The interesting function here is:

- `0x100809A18` `___lldb_unnamed_symbol44409` (see `out/dis_1008099F0.s`)

High-level behavior of `44409`:

1. It checks `[x0 + 0x28]` and returns early if null.
2. It sets up an out-struct on the stack at `sp+0x8` and calls the StoreGetLyrics response parser:

   - `bl 0x100809304` (`___lldb_unnamed_symbol44397`)

3. It then loads `[x0 + 0x28]` again, and if non-null, performs a virtual call at vtable offset `0x30` on that object:

   - `ldr x8, [vtable, #0x30]!` then `blraa x8, x17`
   - It passes `x1 =` the original `x1` argument, and `x2 = sp+0x8` (pointer to the parsed response struct).

My current guess: `44409` is a virtual "deliver response" override for StoreGetLyricsRequest. It parses the response into `StoreGetLyricsRequest::Response` and forwards it to a completion handler object stored at `[this+0x28]`.

I confirmed `44409` is actually in the StoreGetLyricsRequest vtable via fixup-chain details:

- `out/dyld_fixup_chain_details_arm64e.txt` contains:
  - vtable entry at `0x01DD6E58` -> target `0x00000809A18` with diversity `0x6A0F`

Given the vtable addresspoint is `0x101DD6CA0`, the entry lives at:

- `0x101DD6E58` which is offset `0x1B8` from the vtable addresspoint.

So we have a concrete vtable slot to hunt for in virtual dispatch code.

##### New anchor: LyricsHandler/TSL strings in __cstring

I looked for more lyrics-related cstrings (something I can xref into code).

```sh
dyld_info -arch arm64e -section __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg -n "mCurrentLyricsHandler|StoreLyrics|LyricsTagParser|TSLLyrics" | head -n 50
```

Two nice short anchors showed up:

- `mCurrentLyricsHandler`
- `inHandler == mCurrentLyricsHandler`

I pulled their start addrs via otool (since dyld_info gives NUL addresses):

```sh
otool -arch arm64e -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg -n "mCurrentLyricsHandler|inHandler == mCurrentLyricsHandler" | head
```

Start addresses:

- `mCurrentLyricsHandler` at `0x101A76A2E`
- `inHandler == mCurrentLyricsHandler` at `0x101A76ADB`

Then I xref'd `mCurrentLyricsHandler`:

```sh
python3 scripts/find_arm64_adrp_add_xrefs.py --target 0x101A76A2E | tee out/adrp_add_xrefs_mCurrentLyricsHandler.txt
```

Result:

- xref at `0x10118A1EC`

Disassembling around this xref:

- `out/dis_101189C88.s` (function start)
- `out/dis_10118A160.s` (mid-function region containing the xref)

This string appears inside an assertion-failure reporting path (it builds an error log with `"Assertion failure"` and a message including `"mCurrentLyricsHandler"`), so it's not yet the "main pipeline" but it still gets me into the relevant subsystem.

##### Big discovery: TSLLyricsXMLParser.cpp asserts are embedded as cstrings

I also noticed the binary contains very long assert strings that include:

- actual source file paths (AppleInternal build roots)
- full condition strings
- sometimes even large inlined lambda text blobs

Example entries from `dyld_info __cstring`:

- `TSLLyricsTextElement::ParseXML( node, treeNode )`
- `TSLLyricsViewController::ClearHighlight`
- many strings pointing at `/.../TSLLyricsXMLParser.cpp` with explicit line numbers

This is a huge opportunity: I can use these as static anchors to locate the TTML/XML parsing entrypoints, then connect that back to the StoreGetLyrics response `"ttml"` path.

Next step: I probably need another small scanner to locate vtable-dispatch sites by their `movk x17, #<diversity>, lsl #48` constants (e.g. `0x75AF` for the param builder slot, `0x6A0F` for the response handler slot, etc.).

---

### 2026-02-07: Lyrics pipeline deep dive (StoreGetLyricsRequest scheduling + callback plumbing)

Context/time sanity:

```sh
date
git status -sb
```

(As of this moment: `Sat Feb  7 19:04:17 EST 2026`, `HISTORY.md` modified, untracked `scripts/find_arm64_movk_xrefs.py`.)

#### Found: LyricsHandler allocates + schedules a StoreGetLyricsRequest

I disassembled a lyrics-ish handler function at:

- `Music` `___lldb_unnamed_symbol86671` @ `0x1011880A0`
- Disasm: `out/dis_1011880A0.s`

This function looks extremely much like a `LyricsHandler::StartGettingStoreLyrics()` (or the concrete method that creates/schedules the request).

Key behavioral notes:

- Allocates `0x180` bytes via `operator new(size, std::nothrow)`.
- If allocation fails: bails.
- Constructs `StoreGetLyricsRequest` with:
  - `x1 = *(handler + 0x30)` (some store/lyrics id)
  - `w2 = 2 or 3` based on a config/flag byte: if `*(handler + 0x5) == 0` -> `2`, else `3`.
  - I saw this implemented with `cinc` (conditional increment).
- Builds a `shared_ptr` control block (0x20 bytes) and calls a helper that I initially misinterpreted (see below).
- Stores a shared_ptr-like pair into `*(handler + 0x68)` (likely `mLyricsRequest`).
- Calls a schedule method on the request.

A few concrete assembly snippets (trimmed to the telling bits):

```asm
; allocate 0x180 nothrow
mov     w0, #0x180
adrp    x1, ___ZSt7nothrow@PAGE
add     x1, x1, ___ZSt7nothrow@PAGEOFF
bl      _operator_new(unsigned long, std::nothrow_t const&)
cbz     x0, <return>

; compute flags 2/3
ldrb    w8, [x20, #5]
mov     w2, #2
cinc    w2, w2, ne

; ctor(this=x0, id=[handler+0x30], flags=w2)
ldr     x1, [x20, #0x30]
bl      0x100809000 ; ___lldb_unnamed_symbol44392 (StoreGetLyricsRequest::ctor)

; store request shared_ptr-ish into handler+0x68
stp     x0, x1, [x20, #0x68]

; schedule request
mov     x0, x22
bl      0x1007F5FAC ; ___lldb_unnamed_symbol43916 (StoreRequest::Schedule-like)
```

This is a big milestone: it confirms the “lyrics fetch” pipeline is implemented as a StoreRequest subtype, allocated from the handler, stored on the handler, then scheduled.

#### Correction: 0x1007F3990 is weak-self initialization + “Created” logging

I previously thought `0x1007F3990` (`___lldb_unnamed_symbol43896`) was the “completion hookup”. That was wrong.

Disasm: `out/dis_1007F3990.s`

What it does:

- Treats `(x0=this=request, x1=&shared_ptr_pair)`.
- Loads `(ptr, control)` from `*x1`.
- Atomically increments the count at `[control + 0x10]`.
- Stores `(ptr, control)` into `[this + 0x8]` (looks like weak-self / enable_shared_from_this storage).
- Releases any previous weak count via `std::__shared_weak_count::__release_weak()`.
- Logs a message of the form:
  - `storereq> %{public}s(%d). Created.`
  - where the `%{public}s` comes from a virtual “op name” or similar.

This makes `0x1007F3990` feel like a base facility: “the request is now owned by a shared_ptr; store the weak backpointer; emit Created log”.

#### StoreGetLyricsRequest ctor and base init zeroing: explains why +0x28 starts null

`StoreGetLyricsRequest` ctor:

- Address: `0x100809000` `___lldb_unnamed_symbol44392`
- Disasm: `out/dis_100809000.s`

It calls a base init (`0x1007B5638` `___lldb_unnamed_symbol42007`), then sets fields:

- `[this + 0x170] = id`
- `[this + 0x178] = flags`

Base init chain:

- `0x1007B5638` -> calls `0x1007F36C8` (`___lldb_unnamed_symbol43891`)
- Disasm: `out/dis_1007F36C8.s`

The important discovery here: base init explicitly zeroes a 16-byte field at `this + 0x20` via:

- `0x100556794` (`___lldb_unnamed_symbol31464`): `stp xzr, xzr, [x0]`
- Disasm: `out/dis_100556794.s`

So `*(this + 0x20)` and `*(this + 0x28)` are guaranteed to start out as null pointers.

That matters because the response forwarder (`0x100809A18`) *loads `[request + 0x28]` and bails if null*. Therefore, there MUST be a later path that populates this `(ptr0, ptr1)` pair before responses can be handled.

#### New type insight: `this+0x20` is a 16-byte “pair” of intrusive-refcounted pointers

I disassembled:

- `0x1007484C8` (`___lldb_unnamed_symbol39799`)
- Disasm: `out/dis_1007484C8.s`

This function assigns a 16-byte structure that looks like:

- two pointers (`ptrA`, `ptrB`)
- each points to an object with an *intrusive refcount at `[obj + 0x8]`*
  - atomic inc on assign
  - atomic dec on overwrite/release
  - delete if refcount hits 0

This strongly suggests:

- request+0x20 is a “pair of intrusive_ptr-like things”
- request+0x28 is the second pointer in that pair

So when `StoreGetLyricsResponse` forwarder loads `[req+0x28]`, it’s likely reading the “callback receiver” (or similar) from that intrusive-pair.

#### StoreGetLyricsResponse forwarder re-confirmed (and now interpreted via the pair)

- Forwarder: `0x100809A18` (`___lldb_unnamed_symbol44409`)
- Disasm: `out/dis_1008099F0.s`

Behavior:

- Parses response (calls `0x1008099F0` region / `___lldb_unnamed_symbol44397`).
- Loads `x0 = [request + 0x28]`.
- If `x0 == 0`, returns.
- Calls virtual method at vtable offset `0x30` on that object (diversity `0x2B6C`) with the parsed response struct.

Now that I know `request+0x28` is part of an intrusive pair, I’m treating it as “the lyrics callback sink” stored elsewhere.

#### 0x100809654 (44398) does NOT set +0x28; it configures a different field (+0x88)

I chased `StoreGetLyricsRequest` method `0x100809654` (`___lldb_unnamed_symbol44398`) and found:

- It constructs some wrapper objects (`44402`, `44401`) and calls:
  - `0x1007F8FB0` (`___lldb_unnamed_symbol43934`)

`43934` (disasm: `out/dis_1007F8FB0.s`) takes a mutex, checks `[this + 0x128]` (start flag?), and assigns a field at `this + 0x88` via helper functions `44004`/`44003`.

So `44398` is configuring *something*, but it’s the +0x88 slot, not the +0x20/+0x28 pair.

#### Breakthrough: there IS a helper that copies a “pair” into request+0x20 (indirectly populating +0x28)

I found a helper:

- `0x1007F3B40` (`___lldb_unnamed_symbol43899`)

It (under a mutex) assigns `*(this + 0x20) = *(x1)` using the 16-byte-pair assignment helper `39799`.

I then used my BL-xref scanner:

```sh
python3 scripts/find_arm64_bl_xrefs.py --target 0x1007F3B40
```

and found only two callsites:

- `0x1007FA9EC`
- `0x1007FAB4C`

Disasm around them:

- `out/dis_1007FA8D0.s`
- `out/dis_1007FAA80.s`

Both look like they do:

```asm
ldr x0, [sp, #0xb0]      ; request-like object
add x1, x19, #0x20       ; source pair address
bl  0x1007F3B40          ; copies into req+0x20
```

So there is a real “set callback pair” API; it just wasn’t the place I expected (`44398`).

Open question: those two callsites don’t yet look lyrics-specific. Next step is to find *lyrics-specific* code that uses either:

- this `43899` setter, or
- direct calls to `39799` where `x0 = request + 0x20`

I wrote a new scanner (`scripts/find_arm64_movk_xrefs.py`) to help find virtual dispatch sites by their `movk x17, #<diversity>, lsl #48` constants so I can more quickly locate relevant vtable calls and track them back to lyrics-related objects.

#### Follow-up: confirmed StartGettingStoreLyrics sets +0x88 handler, but still no obvious +0x20/+0x28 population

I re-opened the full disassembly for `0x1011880A0` (`out/dis_1011880A0.s`) to make sure I didn’t miss an assignment to the `request+0x20` pair.

Notable additional details I hadn’t captured in my earlier quick snippet:

- After constructing the request + shared_ptr control block, the handler calls `0x1007F3990` (weak-self init + Created log) exactly as expected.
- Later, it constructs a fairly large stack “callable” object (allocates `0x50` bytes for a heap object with vtable diversity `0x5B4C`, stores various captured fields, including the lyrics id at `[obj+0x48]`).
- It passes `&stackCallable` into `StoreGetLyricsRequest` method `0x100809654` (`44398`).
  - Disasm of `44398`: `out/dis_100809654.s`
  - `44398` only builds a wrapper object with diversity `0x1DA3` and calls `0x1007F8FB0` (`43934`).
- `43934` is clearly a setter for the request’s field at `this+0x88` (under mutex at `this+0xE0`).

Key conclusion: the LyricsHandler path DOES set up a callback-ish thing, but it lands in the request at `+0x88`, not in the `+0x20/+0x28` intrusive pair that `StoreGetLyricsResponse` forwarder (`44409`) uses.

#### Schedule() also doesn’t seem to set +0x20

I scanned `StoreRequest::Schedule` (`0x1007F5FAC`, disasm `out/dis_1007F5FAC.s`) for any obvious assignment into `this+0x20` / calls into `39799` but didn’t spot it.

This makes it increasingly likely that the `this+0x20` pair is populated by some other request lifecycle phase (possibly “start performing” / “response handler install” code) or via a tailcall wrapper into `39799` that my BL-xref approach doesn’t see (because tailcalls use `b`, not `bl`).

Next tactical move: find *branch* (B) xrefs to `0x1007484C8` (`39799`) to identify wrapper methods like:

```asm
add x0, x0, #0x20
b   0x1007484c8
```

If such a wrapper exists, it will tell me that there is an official “setter” for the `+0x20` pair, which I can then xref to find the actual place where lyrics installs its callback receiver.

#### 2026-02-07 19:10-19:46

This is the “tailcall thunk + lyrics asset data + TTML parser” binge. I’m writing this as close to real-time as possible, but I’m also backfilling a few steps based on the disassembly artifacts I produced in `out/` during this block.

**New tooling: unconditional branch (B) xref scanner**

I implemented a complementary scanner for tailcalls/thunks that use `b` instead of `bl`:

- Script: `scripts/find_arm64_b_xrefs.py`
- Motivation: lots of tiny wrappers are literally:

```asm
add x0, x0, #0x20
b   <real_function>
```

and my `BL` xref tool won’t see those.

Notable commands during this period:

```sh
python3 scripts/find_arm64_b_xrefs.py --target 0x1007484C8
python3 scripts/find_arm64_movk_xrefs.py --imm16 0x670e --rd 17 > out/movk_xrefs_670E_x17.txt
```

**Major re-interpretation: “current lyrics” global is `shared_ptr` to a lyrics AssetData**

I had previously suspected a global was “current handler”, but the pointer authentication constants told a different story.

In the LyricsHandler response path I saw repeated authentication of a global pointer with:

```asm
movk x17, #0x670e, lsl #48
autda x16, x17
```

This same `0x670e` constant shows up as the vptr-auth constant for the *lyrics asset data* object, not the handler itself. The handler later compares `assetData+0x38` against the handler’s `lyricsId` which strongly implies:

- `assetData + 0x38` = lyricsId
- the global is a `shared_ptr<AssetData>` for “current lyrics asset data”

**Concrete downstream consumer found: `0x10038E628` (21817)**

After scanning for `movk x17, #0x670e, lsl #48` xrefs, I found a strong consumer:

- Consumer: `0x10038E628` (`___lldb_unnamed_symbol21817`)
- Disasm: `out/dis_10038E628.s`

Its behavior (high-level):

- Input: `shared_ptr` to the lyrics AssetData.
- Calls an AssetData virtual at vtable offset `0x10` (diversity `0x7AEA`) to validate / check readiness.
- Extracts `lyricsId` from `assetData+0x38`.
- Copies an intrusive-pair from `assetData+0x40`.
- Extracts a lyrics CFString from `assetData+0x20` via `0x101186AD4` (see below).
- Parses TTML via `0x101729D98` and stores the result into a field at `this+0x1d0`.

Key snippet (call into TTML parse):

```asm
; from out/dis_10038E628.s
bl     0x101186ad4               ; ___lldb_unnamed_symbol86634 (extract CF TTML data)
...
add    x8, sp, #0x10             ; sret out
mov    x0, sp                    ; input wrapper holding CFData*
bl     0x101729d98               ; ___lldb_unnamed_symbol108718 (TTML parser)
```

**Lyrics CFString extractor: `0x101186AD4` (86634)**

- Function: `0x101186AD4` (`___lldb_unnamed_symbol86634`)
- Disasm: `out/dis_101186AD4.s`

This function pulls the “lyricsCFString” out of `assetData+0x20`, asserts it is non-null, and converts it into a CoreFoundation object that downstream code treats as “TTML data”.

**TTML parser identified: `0x101729D98` (108718)**

- Parser: `0x101729D98` (`___lldb_unnamed_symbol108718`)
- Disasm: `out/dis_101729D98.s`

This is a large routine that:

- Builds/uses a CFXML tree (later asserts `xmlTree != __null`).
- Produces a `shared_ptr` return value via the arm64 ABI `x8` sret pointer.
- Post-processes parsed sections/lines and emits warnings like:
  - `WARNING: Detected missing instrumental section at %g of length %g; inserting section`
  - `WARNING: Detected missing instrumental section at end of song of length %g; inserting section`

This strongly supports: the lyrics payload is TTML (XML-ish), parsed into an internal model that includes explicit “instrumental” sections when gaps exceed a threshold.

**Wrapper confirms input type: `cfTTMLData != nullptr`**

I found a small wrapper that asserts the input is CoreFoundation “TTML data” and then calls the parser:

- Wrapper: `0x101719484` (`___lldb_unnamed_symbol108432`)
- Disasm: `out/dis_101719484.s`

Key excerpt:

```asm
; expects a CF* data object on stack (cfTTMLData != nullptr)
mov    x8, x19                    ; sret out
bl     0x101729d98                ; ___lldb_unnamed_symbol108718
```

The assertion string is literally `"cfTTMLData != nullptr"`, which (combined with the earlier extractor) implies:

- we store lyrics as a CFString somewhere, then convert to CFData for parsing.

**XML enumeration helper: `0x1017296F4` (108714)**

- Function: `0x1017296F4` (`___lldb_unnamed_symbol108714`)
- Disasm: `out/dis_1017296F4.s`

This helper walks a `CFTreeRef` and uses CFXML APIs:

- `CFTreeGetChildCount`
- `CFTreeGetChildAtIndex`
- `CFXMLNodeGetTypeCode`

It’s used as a generic “enumerate children and call callback” primitive. An embedded assert string includes a huge source-level snippet referencing:

- `TSLLyricsXMLParser.cpp`
- `TSLLyricsLine::ParseXML(...)`
- `WARNING: Dropping empty line, time span %g - %g`

So there is strong evidence that the TTML parsing implementation is in a component named `TSLLyricsXMLParser` and constructs `TSLLyricsLine` objects.

**RemoteAssetDownloadManager (offline download lyrics) insertion path finally decoded**

Earlier I had a known insertion/log path around:

- `0x10145811C` (`___lldb_unnamed_symbol97647`) containing the string `"radm> lyrics"`

I found the actual higher-level dispatcher `0x101457D3C` (`___lldb_unnamed_symbol97646`) and a thunk:

- Thunk: `0x101458C90` (`___lldb_unnamed_symbol97650`)

Key thunk snippet:

```asm
sub    x0, x0, #0x100
b      0x101457d3c               ; ___lldb_unnamed_symbol97646
```

So this is a classic C++ this-adjusting thunk (likely multiple inheritance / vtable layout).

I then used fixups + movk-xrefs to connect the call sites:

- `out/dyld_fixup_chain_details_arm64e.txt` includes:
  - `target: 0x00001458C90` (thunk) with diversity `0x398E`
- `python3 scripts/find_arm64_movk_xrefs.py --imm16 0x398e --rd 17` found the only two call sites:
  - `0x100ACE660`
  - `0x100ACE924`

Those call sites are in the “command execution” machinery (`out/dis_100ACE600.s`, `out/dis_100ACE8C0.s`) and invoke a vtable entry with diversity `0x398E`, which resolves to the thunk above, which tailcalls into `97646`.

Within `97647`, there are explicit log strings proving what “radm” means:

- `RemoteAssetDownloadManager::SetDownloadedTrackLyrics: HTTPError: %d`
- `RemoteAssetDownloadManager::SetDownloadedTrackLyrics: track lyrics insertion error: %d`

So: `"radm> lyrics"` is “RemoteAssetDownloadManager > lyrics”.

At this point, I’m treating the project as having two major lyrics flows:

- **On-the-fly lyrics display flow**:
  - Store lyrics response -> AssetData -> extract TTML -> parse into `TSLLyrics*` objects -> UI/lyrics model update.
- **Offline/download lyrics flow**:
  - RemoteAssetDownloadManager command -> insert downloaded lyrics assets (with HTTP error handling and insertion error logging).

Next immediate task: connect the LyricsHandler “StoreGetLyrics” response path cleanly into the TTML parse consumer chain (I’ve now found at least one direct callsite from the LyricsHandler cluster into the `21815/21817` consumer, so this should be tractable).

#### 2026-02-07 19:46+

I went hunting for where the `21817` consumer is actually invoked from, and found a direct call out of the LyricsHandler cluster.

Commands:

```sh
python3 scripts/find_arm64_bl_xrefs.py --target 0x10038E3D4
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x101187120 -c 220 -b -r" -o "quit" > out/dis_101187120.s
```

Findings:

- Caller: `0x101187120` (`___lldb_unnamed_symbol86656`)
- Disasm: `out/dis_101187120.s`

This function:

- Takes an AssetData-like pointer and calls the virtual at vtable offset `0x10` with diversity `0x7AEA` (same “validate/has-lyrics” check I saw in `21817`).
- Calls `0x10038E3D4` (`___lldb_unnamed_symbol21815`) which constructs a helper object and then calls the downstream vmethod `21817` (diversity `0x7667`) that extracts TTML and invokes the TTML parser.

Key excerpt:

```asm
; from out/dis_101187120.s
movk   x17, #0x670e, lsl #48
...
movk   x17, #0x7aea, lsl #48
blraa  x8, x17                    ; assetData->(v+0x10) “is valid?”
...
add    x8, sp, #0x40              ; sret for shared_ptr out of 21815
add    x0, sp, #0x30
add    x1, sp, #0x20
bl     0x10038e3d4                ; 21815 -> calls 21817 -> calls 108718
```

It also contains assert strings:

- `"inLyrics != nullptr"`
- `"lyricsEvent != nullptr"`
- `"playActivityFeed != nullptr"`

So `86656` looks like a lyrics-to-play-activity-feed bridge: it’s invoked when lyrics are available, and it kicks off the “consume AssetData -> parse TTML -> build UI model” chain.

#### 2026-02-07 20:00+

Continuing from the `bag://musicSubscription/(lyrics|ttmlLyrics)` discovery.

I wanted to understand what `0x10074AC44` (`___lldb_unnamed_symbol39840`) is doing, since `43920` calls it right after constructing the literal string `"bag://"`.

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10074AC44 -c 260 -b -r" -o quit > out/dis_10074AC44.s
```

Findings:

- `0x10074AC44` (`39840`) is a *prefix/equality* style compare for the project’s `ITString`-like type.
- In the `flags == 0` path it explicitly checks `len(haystack) >= len(needle)` before doing a 16-bit character compare loop.
  - That pattern matches a `HasPrefix`/`StartsWith` primitive.
- In the `flags != 0` path (used by `43920` because it passes `w2 = 0x1B1`) it forwards into `0x10074AE34` (`39841`) after some optional `os_log_type_enabled` gating.

Key excerpt (supports “prefix” semantics):

```asm
; out/dis_10074AC44.s
; ...
cbz    w21, 0x10074acc4              ; if flags==0, do length/compare locally

; flags==0 path:
ldr    x8, [x20]
ldr    x21, [x8]                     ; x21 := len(haystack)
mov    x0, x19
bl     0x1007487f8                   ; 39805: len(needle)
cmp    x21, x0
b.lo   0x10074ad10                   ; if len(haystack) < len(needle) => false

; then compares UTF-16 chars for (len(needle))
ldrh   w8, [x10], #0x2
ldrh   w9, [x20], #0x2
cmp    w8, w9
...
```

So: inside `43920`, the `0x10074AC44(..., "bag://", 0x1B1)` call is very plausibly the guard “URL begins with bag://”.

More details on the `43920` (“request has URL / bag://”) decision:

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1007488E0 -c 120 -b -r" -o quit > out/dis_1007488E0.s
```

- `0x1007488E0` (`___lldb_unnamed_symbol39808`) returns `w0 = 1` when the `ITString`-like object is empty / null, and `w0 = 0` when it contains a backing buffer.
- That matches the control flow in `43920`: if empty -> it logs `"Request has no URL."`, else it goes down the `bag://` resolution path.

Key excerpt:

```asm
; out/dis_1007488E0.s
; if string has backing storage -> return 0
ldr    x8, [x0]
cbz    x8, <check other repr>
ldr    x8, [x8]
cbz    x8, <check other repr>
mov    w0, #0
ret

; else return 1 when length==0 or repr missing
...
```

I also disassembled the `"split by '/'"` helper used by `43920`.

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10074BDC8 -c 240 -b -r" -o quit > out/dis_10074BDC8.s
```

- `0x10074BDC8` (`___lldb_unnamed_symbol39858`) takes `(ITString haystack, ITString delimiter, outObj in x8)`.
- It converts `haystack` into a `CFString` via `CFStringCreateWithCharactersNoCopy` and then feeds it into a CF/Foundation-ish splitting routine (`38969`).
- In `43920`, this is invoked with delimiter `"'/'"`, which fits the pattern of parsing `bag://musicSubscription/lyrics` into path components.

Key excerpt:

```asm
; out/dis_10074BDC8.s
bl     0x1017f3654               ; CFStringCreateWithCharactersNoCopy
...
bl     0x10072466c               ; 38969: likely split/parse into outObj (x8)
```

More `bag://` resolution details (continuing under the same `2026-02-07` local time section).

I wanted to understand what happens after the bag key has been resolved into a “real” URL string, specifically:

- how `bag://...` becomes a `CFURLRef`
- what validations are applied before the request proceeds

##### `bag://` string -> CFURL

`43920` calls `0x1003E0E24` (`23735`) with:

- `x0 = sp+0x90` (out param)
- `x1 = sp+0x68` (resolved URL string; initially came from `bag://...`)

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1003E0E24 -c 260 -b -r" -o quit > out/dis_1003E0E24.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1007242DC -c 220 -b -r" -o quit > out/dis_1007242DC.s
```

Findings:

- `0x1003E0E24` (`23735`) is basically:
  1. build a `CFStringRef` from the project’s `ITString`-like object
  2. build a `CFURLRef` from that CFString via `CFURLCreateWithString`

Key excerpt:

```asm
; out/dis_1003E0E24.s
add    x0, sp, #0x8
bl     0x1007242dc               ; 38954: make CFString from ITString
add    x1, sp, #0x8
mov    x0, x19
bl     0x100724964               ; 38985: CFURLCreateWithString
```

And `38954` confirms the “ITString -> CFString” conversion:

```asm
; out/dis_1007242DC.s
mov    x8, x1
...
ldr    x1, [global CFAllocator]
mov    x0, x8
bl     0x1007490f4               ; 39811: returns CFStringRef
str    x0, [x19]                 ; store into wrapper
```

So the “resolved URL string” is converted into a CFURL at this stage.

##### CFURL validations (host present + https scheme)

In `43920`, immediately after creating the CFURL (`sp+0x90`), there are two checks:

- `0x10072606C` (`39013`)
- `0x100724CB8` (`38995`)

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10072606C -c 200 -b -r" -o quit > out/dis_10072606C.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x100724CB8 -c 240 -b -r" -o quit > out/dis_100724CB8.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x100725074 -c 220 -b -r" -o quit > out/dis_100725074.s
```

`39013` checks that the CFURL can be decomposed *and* has a non-empty hostname.

Key excerpt:

```asm
; out/dis_10072606C.s
ldr    x0, [x0]
cbz    x0, <fail>
bl     CFURLCanBeDecomposed
cbz    w0, <fail>
mov    x8, sp
mov    x0, x19
bl     0x100725074               ; 39000: extract hostname
mov    x0, sp
bl     0x1007488e0               ; 39808: empty?
eor    w19, w0, #0x1             ; return !empty
```

And `39000` is literally `CFURLCopyHostName`:

```asm
; out/dis_100725074.s
ldr    x0, [x0]
cbz    x0, <ret>
bl     CFURLCopyHostName
...
```

`38995` verifies that the URL scheme is exactly `"https"`:

```asm
; out/dis_100724CB8.s
mov    x8, sp
bl     0x100724b20               ; 38991: extract scheme into ITString (sp)
adrp   x1, ... ; "https"
mov    x0, sp
bl     0x10074ab2c               ; 39839: compare
cset   w19, eq                   ; return (compare == 0)
```

So: the bag lookup must resolve to an HTTPS URL with a hostname, otherwise this request path bails.

#### 2026-02-07 20:26-20:30

Quick sanity check on local time and HISTORY structure (prompted by noticing a mismatch between local time and an earlier header).

Commands:

```sh
date
git status --porcelain=v1 -b
rg -n "^#### 2026-02-" HISTORY.md
rg -n "^#### 2026-02-08" HISTORY.md
```

Observed:

- Local machine time is `Sat Feb  7 20:26:46 EST 2026`.
- No remaining `2026-02-08` headers in `HISTORY.md` (so the timeline is aligned to *local* time again).
- `HISTORY.md` had uncommitted additions (the CFURL validation notes appended above) and should be committed before continuing.

#### 2026-02-07 20:30-20:45

Goal: finish nailing down the *exact* query parameter keys added by `StoreGetLyricsRequest::AddParameters` (the earlier disasm annotated one key as `"'l'"` which looked suspicious).

##### Confirming the `l` param key (language)

From `out/dis_10080906C.s` (AddParameters at `0x10080906C`), I saw:

- key `"id"` (track/store Adam ID?)
- key `"l"` (locale/language string, sourced from `0x1007576F0` / `40123`)
- key `"itre"` (boolean 0/1 derived from `[this+0x178]` bit0)

LLDB’s comment showed `"'l'"`, but I suspected it was just “repr of a 1-char string”, not an apostrophe-containing literal.

Commands:

```sh
# Find the VM addresses of the cstrings (otool prints address + decoded string)
otool -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg -n "  itre$" 
otool -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg -n "0000000101a323df" || true
```

Results:

- `"itre"` is at `0x0000000101A328E8`
- the single-letter key is indeed `"l"` at `0x0000000101A323DF`

So `StoreGetLyricsRequest` adds a `l=<locale>` query parameter where `<locale>` comes out of `40123`.

##### Finding other code that uses `itre`

Commands:

```sh
python3 scripts/find_arm64_adrp_add_xrefs.py --target 0x101A328E8
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1007F10F0 -c 140 -b -r" -o quit > out/dis_1007F10F0.s
```

Xrefs reported by the script:

- `0x100809140` (lyrics `AddParameters`)
- `0x1007F1120` (inside `___lldb_unnamed_symbol43810`)

The `43810` snippet suggests `itre` is part of a broader “store platform request” parameter/header bundle (not lyrics-specific). It also references `"itrv"` (same cstring neighborhood as `itre`).

Key excerpt:

```asm
; out/dis_1007F10F0.s
adrp   x1, ...
add    x1, x1, #0x8e8            ; "itre"
...
ldrb   w8, [x20, #0x1a4]
str    w8, [sp, #0x8]
...
bl     0x1002688fc               ; wraps the value as a CFNumber/CFType-ish
...
adrp   x1, ...
add    x1, x1, #0x8ed            ; "itrv"
...
```

So: `itre` likely means some iTunes/store environment knob (exact semantics TBD), and lyrics is just reusing the same convention.

#### 2026-02-07 20:45-21:10

Big milestone: found where the `StoreGetLyricsRequest` `id` (`+0x170`) and `flags` (`+0x178`) fields are *set*, and the primary callsite that constructs/schedules the request.

##### Finding the constructor that writes `+0x170` / `+0x178`

I had already inferred from `AddParameters` that:

- `[this+0x170]` is the ID used for the query param `id=...`
- `[this+0x178]` is a flags bitfield (bit0 -> `itre`, bit1 -> TTML bag key)

So I disassembled a chunk around the `StoreGetLyricsRequest` code region and grepped for those offsets.

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x100808000 -c 3200 -b -r" -o quit > out/dis_100808000_3200.s

rg -n "#0x170|#0x178" out/dis_100808000_3200.s | head
```

Key hit: `___lldb_unnamed_symbol44392` at `0x100808FF4`.

It looks like the real `StoreGetLyricsRequest` ctor taking `(id, flags)`:

```asm
; out/dis_100808000_3200.s
Music`___lldb_unnamed_symbol44392:
...
mov    x19, x2                  ; flags
mov    x20, x1                  ; id
bl     0x1007b5638              ; base StoreRequest-ish ctor
...
str    x20, [x0, #0x170]        ; this->mId = id
str    w19, [x0, #0x178]        ; this->mFlags = flags
retab
```

So `+0x170` is indeed the ID field and `+0x178` is the flags field.

##### Finding who calls that ctor (looks like `LyricsHandler::StartGettingStoreLyrics`)

Next, I asked: who calls `0x100808FF4`?

Commands:

```sh
python3 scripts/find_arm64_bl_xrefs.py --target 0x100808FF4
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x101188190 -c 260 -b -r" -o quit > out/dis_101188190.s
```

Only xref:

- `0x101188248: bl 0x100808FF4`

The surrounding code very strongly looks like `LyricsHandler::StartGettingStoreLyrics`:

- it references an assert string `"mLyricsRequest"`
- it stores a `shared_ptr`-shaped pair into `[this + 0x68]` / `[this + 0x70]`

The ctor call site (trimmed) is:

```asm
; out/dis_101188190.s
ldr    x22, [x20, #0x30]        ; id (likely current track storeAdamID)
...
ldrb   w23, [x0, #0x5]          ; some config bool
cmp    w23, #0x0
mov    w8, #0x2
cinc   w2, w8, ne               ; flags = 0x2 if w23==0 else 0x3
mov    x0, x21                  ; this = newly allocated StoreGetLyricsRequest (size 0x180)
mov    x1, x22                  ; id
bl     0x100808ff4              ; StoreGetLyricsRequest(id, flags)
```

This is hugely informative:

- flags is always `0x2` or `0x3`.
- bit1 (`0x2`) is always set, meaning the request always chooses the TTML bag key `bag://musicSubscription/ttmlLyrics`.
- bit0 (`0x1`) is conditional; when set, `AddParameters` sends `itre=1`, otherwise `itre=0`.

I also confirmed the bag-key selection logic in `0x100809754` (`44399`): it chooses `ttmlLyrics` iff `(flags & 0x2) != 0`.

##### What is the `w23` config bit?

The `w23` bit comes from `0x101090124` (`82395`), which returns a pointer to something like a global app context (it asserts `gAppContext != nullptr`). The bool is read from offset `+0x5` in that struct.

I haven't identified the semantic name for that field yet, but it's clearly controlling the `itre` behavior.

#### 2026-02-07 20:53-

Quick sanity check on the date/timeline after a human review comment (they noticed I had briefly written `2026-02-08` earlier, but local time is still the 7th).

Commands:

```bash
date
rg -n "2026-02-08" HISTORY.md
```

Observed:

- `date` shows: `Sat Feb  7 20:53:40 EST 2026`
- There are **no** `2026-02-08` section headers anymore; the only remaining mentions are in my own logged command output about checking for them.

Next: continue from the `StoreGetLyricsRequest` plumbing into the **completion lambda** inside the lyrics handler, and then follow the TTML bytes into whatever parses it (`TSLLyricsSongInfo::CreateFromTTML` or similar) and ultimately updates the now-playing lyrics view.

#### 2026-02-07 21:05-

##### Tracing the Store lyrics completion lambda (from vtable slot to UI update)

Goal: bridge the gap from `StoreGetLyricsRequest::Response` (ttml string) into the on-screen lyrics pipeline.

I started from the wrapper invoke I previously identified (`0x100809A18` / `44409`) which calls the user callback via a vcall at `vtable + 0x30`. So the plan was:

1. find the callback object's vtable
2. read the entry at `+0x30` to get the callback function address
3. disassemble that and follow what it does

Commands I ran (high level):

```bash
nl -ba out/dis_1011880A0.s | sed -n '140,240p'
python3 - <<'PY'
# decode ADRP at 0x101188354 (0xB0006B90) -> page; add 0xFB0 + 0x10
PY
lldb -o "target create /System/Applications/Music.app/Contents/MacOS/Music" \
  -o "memory read --format x --size 8 --count 16 0x101ef9fc0" -o quit
lldb -o "target create /System/Applications/Music.app/Contents/MacOS/Music" \
  -o "disassemble -s 0x1011889b4 -c 260 -b -r" -o quit > out/dis_1011889b4.s
```

Key result: the callback target object allocated in `___lldb_unnamed_symbol86671` has its vtable address-point at:

- vtable address-point = `0x101EF9FC0` (computed from ADRP `0xB0006B90` @ `0x101188354` + `0xFB0 + 0x10`)

Reading the vtable entry at offset `+0x30` (index 6) yields a signed function pointer whose *low* 32 bits point at:

- callback operator() = `0x1011889B4` (`___lldb_unnamed_symbol86694`)

That function signature matches exactly what `44409` passes:

- `x0`: callback object ("this")
- `x1`: error
- `x2`: `StoreGetLyricsRequest::Response*`

From `out/dis_1011889b4.s` (trimmed):

```asm
; ___lldb_unnamed_symbol86694 @ 0x1011889B4
mov    x21, x2                 ; Response*
mov    x19, x1                 ; error
mov    x20, x0                 ; callback object

ldrb   w1, [x2, #0x10]         ; Response.isTTML flag (set by 44397 when "ttml" non-empty)
add    x8, sp, #0x28
mov    x0, x2
bl     0x101186cbc             ; ___lldb_unnamed_symbol86636(response, isTTML, &out_shared_ptr)

; copies Response.lyricsId into object field at +0x40
ldr    x8, [sp, #0x28]
add    x0, x8, #0x40
add    x1, x21, #0x18
bl     0x1007484c8

; stores captured "song id" into object field at +0x38
ldr    x8, [sp, #0x28]
ldr    x9, [x20, #0x48]
str    x9, [x8, #0x38]

; dispatch_async_f(queue, context, work_fn)
mov    w0, #0x28
bl     operator new
...
bl     dispatch_async_f
```

So the callback does *not* parse TTML immediately. It:

- creates a shared_ptr-wrapped object (size `0x50`) that holds:
  - the lyrics text (copied from `Response.text`),
  - a `isTTML` byte,
  - the store song id (`+0x38`),
  - the lyrics id (`+0x40`),
- then enqueues an async continuation (`___lldb_unnamed_symbol86698` @ `0x101188BDC`) with that context object.

The dispatch continuation (`___lldb_unnamed_symbol86698`) does the state update / signaling:

- locks a weak/shared pair from the context (so it can safely reference the lyrics handler)
- clears `mLyricsRequest` on the handler (`stp xzr, xzr, [x20, #0x68]`)
- if there is an error object in the context, calls a handler vfunc (`vtable + 0x68`) with the error (and returns)
- else, stores the shared_ptr lyrics object into handler offsets `+0x80/+0x88` (looks like `mLyricsSongInfo`), and calls the same vfunc with `nullptr` to signal success

This answered a big question: the Store response’s TTML is initially treated as *opaque data*, and TTML parsing likely happens later (or lazily) from that stored object.

##### Found the TTML parse entrypoint: `TSLLyricsSongInfo::CreateFromTTML`

I suspected there’d be a named entrypoint for TTML parsing and got a huge hint from `strings`:

```bash
strings -a /System/Applications/Music.app/Contents/MacOS/Music | rg -n "CreateFromTTML|cfTTMLData|setTTML:" | head
```

This includes multiple demangled-ish strings for:

- `TSLLyricsSongInfo::CreateFromTTML(const __CFData*)`
- plus an assertion string: `cfTTMLData != nullptr`

I then located that assertion string in `__TEXT,__cstring`:

```bash
otool -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg -n "cfTTMLData != nullptr"
```

Result:

- `"cfTTMLData != nullptr"` is at VM addr `0x101AA735E`.

Then I used my ADRP+ADD xref scanner to find where that string is referenced:

```bash
python3 scripts/find_arm64_adrp_add_xrefs.py --target 0x101aa735e
```

Result: a single xref inside a function at `0x101719568`.

Disassembling that region (`out/dis_101719480.s`), I found a very plausible TTML parse helper (`___lldb_unnamed_symbol108432` @ `0x101719484`) that:

- takes some input object, extracts a `CFDataRef` into `sp+0x8`
- asserts/logs if it’s null (`cfTTMLData != nullptr`)
- otherwise creates some CF object via `0x1006E2A00` (looks like an internal “create CFXML tree from data” helper), then calls `0x101729D98` to continue processing

The interesting (and slightly funny) part: the assertion log path uses an unrelated-looking format string:

```asm
; ___lldb_unnamed_symbol108432 @ 0x101719548+
add    x8, x8, #0x35e          ; "cfTTMLData != nullptr"
...
add    x3, x3, #0xff4          ; "Performance shaders not available on this device. Resorting to fallback for effects."
bl     _os_log_error_impl
```

This smells like either a shared logging helper or a reused string constant; either way, the presence of `cfTTMLData != nullptr` in this function makes it a very likely part of the TTML decode path.

Next: keep walking `___lldb_unnamed_symbol108432` (0x101719484) into `___lldb_unnamed_symbol108718` (0x101729D98) and the large helper (`___lldb_unnamed_symbol108433` @ 0x1017195D0) to understand how the CFXML tree is traversed and how timestamps/lines are extracted.

##### TTML XML Parser Deep Dive (TSLLyricsXMLParser.cpp leaked strings + function graph)

Time window: ~21:05-21:17.

I went further and it turns out the binary contains **massive** debug/assert strings that basically include large chunks of the original C++ lambdas (including file paths and line numbers).

Key commands:

```bash
# Find callsites to the TTML entrypoint (108432 @ 0x101719484)
python3 scripts/find_arm64_bl_xrefs.py --target 0x101719484

# Disassemble the TTML callsite and parser helpers
lldb -o "target create /System/Applications/Music.app/Contents/MacOS/Music" \
  -o "disassemble -s 0x101186b80 -c 260 -b -r" -o quit > out/dis_101186b80.s

# Disassemble key parser functions
lldb ... -o "disassemble -s 0x1017294a4 -c 520 -b -r" -o quit > out/dis_1017294a4.s
lldb ... -o "disassemble -s 0x101728e04 -c 520 -b -r" -o quit > out/dis_101728e04.s
lldb ... -o "disassemble -s 0x101728ef0 -c 520 -b -r" -o quit > out/dis_101728ef0.s
```

###### The missing bridge: the Store lyrics object calls into `CreateFromTTML`

The only BL xref to `0x101719484` (`108432`) is:

- callsite: `0x101186C5C`

That’s inside `___lldb_unnamed_symbol86635` (`out/dis_101186b80.s`), which appears to be a method on the *opaque* lyrics object created in the Store completion callback (the one storing TTML as an `ITString` + `isTTML` byte).

Trimmed key path:

```asm
; ___lldb_unnamed_symbol86635 @ 0x101186c0c
; vcall at vtable+0x18 returns the isTTML byte (matches vtable entry 86643 -> ldrb w0, [x0,#0x30])
ldr    x16, [x20]
...    autda ...
ldr    x8, [x16, #0x18]!
blraa  x8, x17                 ; returns w0
cbz    w0, fallback

; parse TTML (ITString at this+0x20) into a shared_ptr<...> via 108432
add    x0, x20, #0x20
mov    x8, sp
bl     0x101719484             ; ___lldb_unnamed_symbol108432

; if result non-null, continue with 108433
ldr    x21, [sp]
cbz    x21, skip
mov    x8, x19
mov    x0, x21
bl     0x1017195d0             ; ___lldb_unnamed_symbol108433
```

This is the clean end-to-end connection:

1. Store response gives TTML string.
2. Store completion creates an opaque lyrics object storing TTML as an `ITString` + `isTTML`.
3. Later, when the app needs parsed timed lyrics, it calls this method (`86635`), which calls the TTML parser entrypoint (`108432`).

###### TTML time parsing: `begin`/`end` + colon-separated time strings

`___lldb_unnamed_symbol108709` (`0x101728E04`) reads TTML attributes:

- `"begin"` -> stores `double` to `[this + 0x40]`
- `"end"` -> stores `double` to `[this + 0x48]`

It obtains attribute values via `108708` and converts via `108710` (`0x101728EF0`).

`108710` is a time-string parser that splits on `":"` and uses `60.0` (double constant `0x404e000000000000`) to do `minutes * 60 + seconds` style accumulation (it looks like it supports `hh:mm:ss` too).

###### TTML parsing high-level structure (from the lambda code strings)

By chasing the vtables used with `EnumerateTreeChildren` (which is `___lldb_unnamed_symbol108714` @ `0x1017296F4`) and disassembling the call-operators, the TTML structure is very clear:

1. Root `<tt>`
  - extracts attributes:
    - `itunes:lyricGenId`
    - `xml:lang`
  - then enumerates children
2. `<head>`
  - enumerates `<metadata>`
  - within that, enumerates `iTunesMetadata`
  - within that, enumerates:
    - `Songwriters` -> `Songwriter` -> `TSLLyricsSongWriter::ParseXML`
    - `Translations` -> `Translation` -> `TSLLyricsTranslation::ParseXML`
3. `<body>`
  - extracts attribute `dur` -> stores song duration (double)
  - enumerates:
    - “section” nodes (looks like `div`)
    - “line” nodes (looks like `p`)

Most importantly: the binary contains assert strings that literally include (very long) lambda source code and the path:

- `/.../MusicDesktop/iTunes/Application/TSL/TSLLyricsXMLParser.cpp`

with line numbers (e.g. 350, 356, 320-335, 166, 192, etc).

###### Section + line parsing behavior

From `out/dis_101729a0c.s` (`___lldb_unnamed_symbol108716`) there’s a string that shows the section parser enumerates its children and creates line objects, with additional behavior:

- If `line->mLyricsText.Trim().IsEmpty()`:
  - logs: `WARNING: Dropping empty line, time span %g - %g`
- Else:
  - sets `line->mParentSection = thisRef`
  - sets `line->mLineIndex = line->mOriginalLineIndex = lyricsLineList.size()`
  - pushes to both `mLines` and the outer `lyricsLineList`

From `out/dis_1017294a4.s` (`___lldb_unnamed_symbol108713`) there’s a string that shows the line parser enumerates children and builds **word-level** timing:

- For each `kXMLElementWord`:
  - allocates `TSLLyricsWord`
  - `word->ParseXML(lineNode, lineTreeNode)`
  - sets `word->mParentLine = line`
  - pushes into `mWords`

This is enough to sketch a pretty faithful graph of the pipeline now:

Store TTML string -> opaque lyrics object -> CreateFromTTML -> CFXML tree -> EnumerateTreeChildren -> build TSLLyricsSongInfo
  - songwriters/translations from head metadata
  - duration + sections(div) + lines(p) from body
    - line begin/end + itunes:key + words from nested nodes

#### 2026-02-07 21:24-

Quick pause to sanity-check the timeline in this notebook, and then continue digging into the TTML `<head>` metadata path (especially songwriters + translations).

##### HISTORY.md date check (local time)

I’m being extra paranoid here because I previously wrote a bad header while reasoning quickly.

Commands:

```sh
date
rg -n "2026-02-0[89]" HISTORY.md
```

Observed:

- `date` shows `Sat Feb  7 21:24:17 EST 2026` (so this session is still on Feb 7, not Feb 8).
- There are **no** `2026-02-08` timeline headers; the only mentions are in my own logged `rg` commands.

##### Mapping the nested `<iTunesMetadata>` lambdas for `<songwriters>` / `<translations>`

I already had the “big picture” from the giant embedded assert strings, but I wanted to nail down the *actual* call operators for the deep nested lambdas so we can extract object layouts and exact offsets.

The `iTunesMetadata` child-enumerator lambda is `___lldb_unnamed_symbol108819` @ `0x10172C22C` (from `out/dis_10172bd94.s`):

- It checks the node name:
  - `"songwriters"` -> enumerates children with another lambda
  - `"translations"` -> enumerates children with another lambda
  - anything else -> `return true` (ignore)

The tricky part is: those child lambdas are referenced only via vtables (created on the stack), so I pulled their operator() addresses out of the vtables.

Commands:

```sh
# Decode the adrp targets for the vtables and read the vtable entries.
python3 - <<'PY'
def decode_adrp(instr: int, pc: int) -> int:
    immlo: int = (instr >> 29) & 0x3
    immhi: int = (instr >> 5) & 0x7FFFF
    imm: int = (immhi << 2) | immlo
    if ((imm >> 20) & 1) == 1:
        imm -= 1 << 21
    page: int = pc & ~0xFFF
    return (page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF

# The relevant adrp in the 108819 body is 0x90004270, and one PC site is 0x10172C350.
print(hex(decode_adrp(0x90004270, 0x10172C350)))
PY

lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "memory read --format x --size 8 --count 24 0x101F78200" \
  -o "memory read --format x --size 8 --count 24 0x101F782F8" \
  -o quit
```

Results:

- vtable address-point `0x101F78200` corresponds to the `<songwriters>` child lambda.
  - vtable entry @ `+0x30` (index 6) points at `0x10172C53C` (`___lldb_unnamed_symbol108828`)
- vtable address-point `0x101F782F8` corresponds to the `<translations>` child lambda.
  - vtable entry @ `+0x30` (index 6) points at `0x10172CAC8` (`___lldb_unnamed_symbol108842`)

I disassembled both into new artifacts:

- `out/dis_10172c53c.s` (songwriter-node lambda operator)
- `out/dis_10172cac8.s` (translation-node lambda operator)

###### Writer node lambda: `___lldb_unnamed_symbol108828` @ `0x10172C53C`

High level behavior:

- Expects each child under `<songwriters>` to be `<songwriter>`.
  - if nodeText != `"songwriter"`: logs assertion `writerNodeText.IsEquivalent( kXMLElementSongwriter )` and returns `false`.
- Allocates `TSLLyricsSongWriter` with `new (std::nothrow)` size `0x58`.
- Calls `writer->ParseXML(writerNode, writerTreeNode)` via vtable slot `+0x18`.
  - on failure: logs assertion `writer->ParseXML( writerNode, writerTreeNode )` and returns `false`.
- On success: pushes `writer` into `songInfo->mSongwriters` (a `std::vector` of `shared_ptr`-ish pairs).

Key excerpt showing the strict node-name check (compare returns 0 on match):

```asm
; out/dis_10172c53c.s
adrp   x1, ... ; "songwriter"
mov    x0, sp
bl     0x100747d98               ; 39785: ITString = "songwriter"
mov    x0, x19                   ; nodeText
mov    x1, sp
mov    w2, #0x1b1
bl     0x10074a03c               ; 39827: compare
cbz    w19, <match>              ; match when compare == 0
; else -> assertion + return false
```

Key excerpt showing `ParseXML` as a vcall at `+0x18`:

```asm
; out/dis_10172c53c.s
ldr    x16, [x20]                ; writer vtable
autda  x16, ...
ldr    x8, [x16, #0x18]!
mov    x0, x20                   ; writer
mov    x1, x21                   ; writerNode (CFXMLNodeRef)
mov    x2, x23                   ; writerTreeNode (CFTreeRef)
blraa  x8, ...
tbz    w0, #0x0, <fail>          ; bool return
```

Very useful layout inference: this lambda captures `songInfo` by reference (`[&]`), so the capture is a `TSLLyricsSongInfo**` (pointer to the local `songInfo` pointer).

When pushing into `songInfo->mSongwriters`, the vector’s fields appear at:

- `songInfo + 0x28` = begin
- `songInfo + 0x30` = end
- `songInfo + 0x38` = end_cap

I’m inferring that from the push_back logic:

- fast path writes at `end`, advances `end`, stores updated `end` back to `[songInfo + 0x30]`
- slow path reads begin from `[songInfo + 0x28]`, reallocates, then stores begin/end/end_cap back to `0x28/0x30/0x38`

###### Translation node lambda: `___lldb_unnamed_symbol108842` @ `0x10172CAC8`

High level behavior:

- Expects each child under `<translations>` to be `<translation>`.
  - if nodeText != `"translation"`: logs assertion `transNodeText.IsEquivalent( kXMLElementTranslation )` and returns `false`.
- Allocates `TSLLyricsTranslation` with `new (std::nothrow)` size `0x60`.
- Calls `translation->ParseXML(transNode, transTreeNode)` via vtable slot `+0x18`.
  - on failure: logs assertion `translation->ParseXML( transNode, transTreeNode )` and returns `false`.
- On success, it effectively implements:

  `songInfo->mTranslationsMap[ translation->mLanguage ] = translation->mTranslationMap;`

Two particularly nice offset hints fall out of the machine code:

- It takes the key from `translation + 0x38` (looks like `translation->mLanguage`).
- The destination map lives at `songInfo + 0x90` (looks like `songInfo->mTranslationsMap`).

Key excerpt:

```asm
; out/dis_10172cac8.s
ldr    x8, [x21, #0x8]            ; capture (&songInfo)
ldr    x8, [x8]                   ; songInfo*
add    x1, x22, #0x38             ; &translation->mLanguage
add    x0, x8, #0x90              ; &songInfo->mTranslationsMap
bl     0x10171bacc                ; 108466: map operator[] / find+insert style helper
```

After the `108466` call, there’s a long loop that walks `translation->mTranslationMap` and inserts/copies into the returned destination map entry (so the value type is almost certainly itself a map/tree-like container, not a flat scalar).

Next: disassemble `0x10171BACC` (`108466`) and the `108874/108875` helpers (`0x10172D9AC` / `0x10172DA24`) to get a clearer idea of:

- what type `mTranslationsMap` is (std::map vs unordered_map vs custom)
- what the inner “translation map” key/value types are

#### 2026-02-07 21:30-21:40

Goal: answer the question I left hanging above: what are the key/value types of the translation maps, and what XML attribute ties translations back to specific body lines?

##### Pulling `TSLLyricsTranslation::ParseXML` from the translation object's vtable

In the translation-node lambda (`108842` @ `0x10172CAC8`) the translation object vtable address-point is computed from:

- `adrp x16, ...` -> page `0x101F78000`
- `add x16, x16, #0x358` + `#0x10` -> vtable address-point `0x101F78368`

I read that vtable to get the `ParseXML` target at offset `+0x18`:

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "memory read --format x --size 8 --count 16 0x101f78368" -o quit

lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10172d098 -c 420 -b -r" -o quit > out/dis_10172d098.s
```

Result:

- `TSLLyricsTranslation::ParseXML` = `___lldb_unnamed_symbol108848` @ `0x10172D098`

Key observations from `out/dis_10172d098.s`:

- It reads `xml:lang` and stores it into `translation + 0x38`:

```asm
; out/dis_10172d098.s
adrp   x1, ... ; "xml:lang"
bl     0x101728b9c               ; 108708: attribute lookup
add    x0, x20, #0x38            ; this + 0x38
bl     0x1007483b0               ; 39796: store/copy ITString
```

- It enumerates child nodes and looks specifically for a `"text"` element (kXMLElementTranslationText).
- The embedded assert string is extremely explicit about the translation map shape:

  `mTranslationMap[ line->mLyricsLineKey ] = line->mLyricsText;`

  where `line` is a `TSLLyricsTranslationText` parsed from the `<text>` element.

So: the per-translation inner map is keyed by a “lyrics line key”, not by timestamp/index.

##### Pulling `TSLLyricsTranslationText::ParseXML` and finding the attribute name for the line key

The `<text>` child lambda allocates `TSLLyricsTranslationText` and calls `ParseXML` on it. I extracted the `ParseXML` target by reading the translation-text object's vtable address-point computed in the lambda:

- `adrp` page `0x101F78000`
- `add #0x410` + `#0x10` -> vtable address-point `0x101F78420`

Commands:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "memory read --format x --size 8 --count 12 0x101f78420" -o quit

lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10172d6ac -c 420 -b -r" -o quit > out/dis_10172d6ac.s
```

Result:

- `TSLLyricsTranslationText::ParseXML` = `___lldb_unnamed_symbol108862` @ `0x10172D6AC`

Key observations from `out/dis_10172d6ac.s`:

- It first calls the shared `TSLLyricsTextElement::ParseXML` (`108711` @ `0x101729048`), so `<text>` inherits the common “begin/end + text content” parsing.
- Then it reads an attribute named `"for"` and stores it into `this + 0x70`:

```asm
; out/dis_10172d6ac.s
adrp   x1, ... ; "for"
bl     0x101728b9c               ; 108708: attribute lookup
add    x0, x20, #0x70            ; likely mLyricsLineKey
bl     0x1007483b0               ; 39796: store/copy ITString
```

This is *very* suggestive:

- Body lines (`<p>`) carry an `itunes:key` attribute (I previously saw it stored into `TSLLyricsLine + 0xC0`).
- Translation text nodes (`<text>`) carry a `for="<key>"` attribute, which I strongly suspect references that same `itunes:key` value.

So the “lyrics key” linking translations to body lines is:

- Original line: `itunes:key="..."`
- Translated line: `<text for="...">translated text...</text>`

This basically explains how the UI can do per-line translations without messing with timestamps.

##### Quick note: `TSLLyricsSongWriter::ParseXML` also exists and is attribute-driven

While I was in the vtable-reading groove, I also chased the song-writer parse function via the writer object's vtable and confirmed it reads an `"artistId"` attribute into `writer + 0x48` (see `out/dis_101729c78.s`). I haven't yet mapped the rest of the writer fields (name text vs role, etc).

Next:

- Map the `<text>` child lambda itself (the one that does `mTranslationMap[key] = text`) so I can pin down the offsets for `TSLLyricsTranslationText::mLyricsText` precisely.
- Continue the UI/consumer-side trace: find where `songInfo->mTranslationsMap` is queried, and how `itunes:key` is used when rendering.

#### 2026-02-07 21:47-: Consumer-side CreateFromTTML callsite at `0x10038E9AC` (and what it does with the result)

Context:

Earlier I found that `TSLLyricsSongInfo::CreateFromTTML` is very likely `___lldb_unnamed_symbol108718` @ `0x101729D98`, and I had 3 callsites. I had already looked at two callsites (one via `108432`, one around `0x101730328`), but the third one was `0x10038E9AC`.

This smells like a more “UI-ish” path (lower in the address space, lots of class/virtual dispatch + strings).

Commands / artifacts:

```sh
# (sanity) local time still Feb 7
date

# disassemble the caller around the CreateFromTTML callsite
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10038e628 -c 420 -b -r" -o quit > out/dis_10038e628.s

# verify the symbol name(s) for a couple addresses to avoid confusion about offsets
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "image lookup -a 0x10038e860" \
  -o "image lookup -a 0x10038e2a0" -o quit

# disassemble the helper used right before CreateFromTTML (CFData construction)
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x101186ad4 -c 420 -b -r" -o quit > out/dis_101186ad4.s

# disassemble the tiny wrapper constructor used at sp+0x40
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10071e3d0 -c 260 -b -r" -o quit > out/dis_10071e3d0.s
```

Key observation: `___lldb_unnamed_symbol21817` @ `0x10038E628` calls `CreateFromTTML`, then immediately reads an `ITString` at offset `+0x50` from the parsed `TSLLyricsSongInfo` object and stores it into `this + 0x1D0`.

Relevant slice (from `out/dis_10038e628.s`):

```asm
; out/dis_10038e628.s
; ...
0x10038e988 <+864>:  ldr    x0, [x20]
0x10038e98c <+868>:  bl     0x101186ad4               ; 86634
0x10038e990 <+872>:  add    x8, sp, #0x40
0x10038e994 <+876>:  bl     0x10071e3d0               ; 38737
0x10038e998 <+880>:  ldr    x8, [sp, #0x40]
0x10038e99c <+884>:  cbz    x8, 0x10038e9e4

; pass __CFData const* const& as a reference (store pointer at [sp], pass x0=&[sp])
0x10038e9a0 <+888>:  str    x8, [sp]
0x10038e9a4 <+892>:  add    x8, sp, #0x10             ; sret: std::shared_ptr<TSLLyricsSongInfo>
0x10038e9a8 <+896>:  mov    x0, sp                    ; arg0: &__CFData*
0x10038e9ac <+900>:  bl     0x101729d98               ; 108718: TSLLyricsSongInfo::CreateFromTTML

; if songInfo != nullptr:
0x10038e9b0 <+904>:  ldr    x8, [sp, #0x10]            ; shared_ptr.get()
0x10038e9b4 <+908>:  cbz    x8, 0x10038e9d8

; copy songInfo + 0x50 (ITString) into this + 0x1D0 (ITString)
0x10038e9b8 <+912>:  mov    x0, sp                    ; dest ITString (stack temp)
0x10038e9bc <+916>:  add    x1, x8, #0x50             ; src ITString (songInfo+0x50)
0x10038e9c0 <+920>:  bl     0x100747c84               ; 39781: ITString copy
0x10038e9c4 <+924>:  add    x0, x19, #0x1d0           ; this+0x1D0
0x10038e9c8 <+928>:  mov    x1, sp                    ; src temp
0x10038e9cc <+932>:  bl     0x1007483b0               ; 39796: ITString store/copy
0x10038e9d0 <+936>:  mov    x0, sp
0x10038e9d4 <+940>:  bl     0x100747c5c               ; 39780: ITString dtor
; ...
```

What this tells me:

- This is a clean, high-confidence confirmation that `108718` returns a `std::shared_ptr<TSLLyricsSongInfo>` by value (AArch64 ABI: hidden sret pointer in `x8`).
- The `__CFData const* const&` argument behavior is exactly what I expected: store the CFData pointer in memory, pass a pointer-to-that-memory.
- There is at least one “consumer” of `TSLLyricsSongInfo` that does *not* walk the per-line/per-word structure; it immediately grabs a single string field at `songInfo + 0x50` and copies it into its own `ITString` field.
  - I don’t yet know if `songInfo+0x50` is “plain lyrics text”, “original TTML”, “a pre-flattened text blob”, or something else, but it’s an `ITString` that’s treated as an important derived product of the TTML parse.

Now: how does this callsite get the CFData for `CreateFromTTML`?

It calls `___lldb_unnamed_symbol86634` @ `0x101186AD4` first. Disassembling `86634` shows it’s basically:

1) Ensure `obj + 0x20` (an `ITString`) is *not empty* using `39808`.
2) Convert that `ITString` to a `CFStringRef` (via `38954`).
3) Convert CFString to CFData using `CFStringCreateExternalRepresentation` with UTF-8 encoding (`kCFStringEncodingUTF8 = 0x08000100`).

The embedded assert string is very explicit:

- `"lyricsCFString != nullptr"`

So `86634` is a very plausible “encode lyrics string as CFData” helper (where the string is likely the TTML payload).

The `38737` helper called right after is almost comically tiny:

```asm
; out/dis_10071e3d0.s
0x10071e3d0 <+0>: str  x0, [x8]
0x10071e3d4 <+4>: strb wzr, [x8, #0x8]
0x10071e3d8 <+8>: ret
```

This looks like construction of a trivial “CFType wrapper” struct at `sp+0x40`:

- `[sp+0x40]` = `CFDataRef`
- `[sp+0x48]` = some boolean/flag byte, set to 0

So the CFData that goes into `CreateFromTTML` is literally the external representation of whatever lyrics string is stored in the upstream object’s `ITString` at offset `+0x20`.

Open questions / immediate follow-ups:

- What exactly is `songInfo + 0x50`? I should locate writes to that offset inside `CreateFromTTML` (or its callees), or search for other consumers that read the same offset.
- What is the type of the upstream “lyrics object” passed into `86634` (the thing that has `ITString` at `+0x20` and another 32-bit field at `+0x34` read earlier in `21817`)?

#### 2026-02-07 21:56-: `TSLLyricsSongInfo` constructor confirms `+0x50` is an `ITString` member (and more context from `CreateFromTTML` + `108914`)

I wanted to get more certainty about what lives at `songInfo + 0x50` beyond “some consumer reads it as an ITString”.

So I disassembled the constructor that `CreateFromTTML` calls right after `operator new(0xA8, nothrow)`.

Commands / artifacts:

```sh
# Disassemble CreateFromTTML itself (large, but useful for seeing the initial allocation + ctor call)
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x101729d98 -c 900 -b -r" -o quit > out/dis_101729d98.s

# Disassemble the constructor it calls (0xA8-sized object)
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x10171b5c8 -c 260 -b -r" -o quit > out/dis_10171b5c8.s

# I also started pulling the longer caller function that uses CreateFromTTML inside 108914:
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" \
  -o "disassemble -s 0x1017301c0 -c 1400 -b -r" -o quit > out/dis_1017301c0_full.s
```

##### `TSLLyricsSongInfo` ctor (`108456` @ `0x10171B5C8`): `+0x40` and `+0x50` are both `ITString` fields

From `out/dis_10171b5c8.s`:

```asm
; out/dis_10171b5c8.s
0x10171b618 <+80>:  add    x0, x0, #0x40
0x10171b61c <+84>:  bl     0x100556794               ; 31464: ITString default ctor

0x10171b620 <+88>:  add    x0, x19, #0x50
0x10171b624 <+92>:  bl     0x100556794               ; 31464: ITString default ctor
```

So the consumer reading `songInfo + 0x50` is absolutely reading a real member field (not some coincidental pointer math).

Other ctor corroborations (nice consistency checks with earlier notes):

- `songInfo + 0x28/+0x30/+0x38` is the songwriters vector (initialized to `{0,0,0}`).
- `songInfo + 0x90` is the translations map, with its header/sentinel node at `songInfo + 0x98`:

```asm
; out/dis_10171b5c8.s
0x10171b62c <+100>: mov    x8, x19
0x10171b630 <+104>: str    xzr, [x8, #0x98]!          ; zero header node @ +0x98
...
0x10171b640 <+120>: str    x8, [x19, #0x90]           ; map header pointer @ +0x90
```

So the offsets I inferred earlier from the translation/songwriter lambdas match the ctor exactly.

##### `CreateFromTTML` (`108718` @ `0x101729D98`) allocates `0xA8` and calls `108456`

Early in `out/dis_101729d98.s`:

```asm
0x101729e0c <+116>: mov    w0, #0xa8                  ; =168
0x101729e10 <+120>: bl     0x1017f7574               ; operator new(nothrow)
0x101729e20 <+136>: bl     0x10171b5c8               ; 108456 ctor
```

##### `108914` also calls `CreateFromTTML` and then uses `songInfo + 0x18` to update the upstream lyrics object’s `+0x34`

While scrolling through `out/dis_1017301c0_full.s`, I hit a section where it:

1) Parses the TTML via `86634` -> `CreateFromTTML` (return `std::shared_ptr<TSLLyricsSongInfo>` at `[sp+0x30]`).
2) Later loads `songInfo` from `[sp+0x30]`, reads `w12 = [songInfo + 0x18]`, and stores that into `w12 -> [lyricsObj + 0x34]` (where `lyricsObj = [x20]`).

Snippet (from `out/dis_1017301c0_full.s`):

```asm
; out/dis_1017301c0_full.s
0x1017305bc <+1020>: ldr    x11, [x20]                ; lyricsObj
0x1017305c0 <+1024>: ldr    x10, [sp, #0x30]          ; songInfo (shared_ptr.get())
0x1017305c8 <+1032>: ldr    w12, [x10, #0x18]         ; songInfo->(field at +0x18)
0x1017305d8 <+1048>: str    w12, [x11, #0x34]         ; lyricsObj->(field at +0x34)
```

This is cool for two reasons:

- It connects the upstream lyrics “holder” object’s `+0x34` field (seen in `21817`) to a concrete field inside `TSLLyricsSongInfo` (`+0x18`), so that upstream object is definitely being “enriched” with parse-derived state.
- `TSLLyricsSongInfo + 0x18` is initialized to `1` in the ctor, but `CreateFromTTML` likely updates it depending on what it finds in the TTML (I saw a lot of logic in `108718` that appears to set a `w?` into `[somePtr + 0x18]` while iterating structures).

Next:

- Find where `TSLLyricsSongInfo + 0x50` gets populated during parsing (probably in a callee of `CreateFromTTML`, since `108718` itself doesn’t obviously touch that offset in the initial 900-instruction dump).
- Keep mining `108914` for actual “consumer logic” that might reference `mTranslationsMap` (offset `+0x90`) or per-line keys.

#### 2026-02-07 21:58-: Big clarification: `songInfo + 0x50` is the root `xml:lang` (and `songInfo + 0x40` is `itunes:lyricGenId`)

I was chasing “who writes `songInfo + 0x50`” and did a brute scan for `add x0, <reg>, #0x50` in `out/dis_*.s`.

Command:

```sh
rg -n "add\\s+x0,\\s*x[0-9]+,\\s*#0x50\\b" out/dis_*.s | head
```

One of the hits was `out/dis_10172b6fc.s`, so I opened it.

Commands:

```sh
sed -n '1,120p' out/dis_10172b6fc.s
```

Result: `___lldb_unnamed_symbol108783` @ `0x10172B6FC` is a root-level TTML parser that:

1) Asserts/validates the root node name is `"tt"`.
2) Reads attribute `"itunes:lyricGenId"` and stores it into `TSLLyricsSongInfo + 0x40` (ITString).
3) Reads attribute `"xml:lang"` and stores it into `TSLLyricsSongInfo + 0x50` (ITString).

Relevant snippet from `out/dis_10172b6fc.s`:

```asm
; out/dis_10172b6fc.s
; ...
; lookup "itunes:lyricGenId" and store into songInfo + 0x40
0x10172b764:  adrp   x1, ... ; "itunes:lyricGenId"
0x10172b780:  bl     0x101728b9c               ; 108708: attribute lookup
0x10172b784:  ldr    x8, [x20, #0x8]
0x10172b788:  ldr    x8, [x8]
0x10172b78c:  add    x0, x8, #0x40
0x10172b794:  bl     0x1007483b0               ; 39796: ITString store/copy

; lookup "xml:lang" and store into songInfo + 0x50
0x10172b7a8:  adrp   x1, ... ; "xml:lang"
0x10172b7c4:  bl     0x101728b9c               ; 108708: attribute lookup
0x10172b7c8:  ldr    x8, [x20, #0x8]
0x10172b7cc:  ldr    x8, [x8]
0x10172b7d0:  add    x0, x8, #0x50
0x10172b7d8:  bl     0x1007483b0               ; 39796: ITString store/copy
```

This is a huge correction to my earlier “songInfo+0x50 might be plain lyrics” speculation.

New interpretation:

- `TSLLyricsSongInfo + 0x50` is *the base language tag for the whole TTML document* (root `xml:lang`).
- `TSLLyricsSongInfo + 0x40` is an iTunes-specific ID-ish attribute (`itunes:lyricGenId`).

This also retroactively makes the `0x10038E9AC` consumer make more sense:

- `21817` copies `songInfo + 0x50` into `this + 0x1D0`.
- So `this + 0x1D0` in that consumer is very likely storing the *lyrics language*, not the lyrics text.

Next:

- Find where the “flattened plain lyrics string” lives (it’s not `songInfo + 0x50`). That likely comes from walking `TSLLyricsLine`/`TSLLyricsWord` or a dedicated “flatten” helper (`108433` looked like a newline join).

#### 2026-02-07 22:05-: `TSLLyricsLine::ParseXML` stores `itunes:key` into `line + 0xC0` (confirming the line-key linkage for translations)

I wanted to re-ground the “line key” hypothesis with actual parse code for `<p>` (line) nodes.

I searched for the literal string `"itunes:key"` in disassembly artifacts.

Command:

```sh
rg -n "itunes:key" out/dis_*.s | head
```

That pointed at `out/dis_1017294a4.s`, so I opened it.

Command:

```sh
sed -n '1,120p' out/dis_1017294a4.s
```

Result: `___lldb_unnamed_symbol108713` @ `0x1017294A4` is a `ParseXML` for a line object (this pointer in `x20`), and it does exactly what I previously inferred:

1) Calls the base `TSLLyricsTextElement::ParseXML` (`108711` @ `0x101729048`) first.
2) Looks up the attribute `"itunes:key"`.
3) Stores that attribute value into `this + 0xC0` as an `ITString`.

Relevant snippet:

```asm
; out/dis_1017294a4.s
0x1017294d8:  bl     0x101729048               ; 108711: TSLLyricsTextElement::ParseXML
; ...
0x1017294e0:  adrp   x1, ... ; "itunes:key"
0x1017294fc:  bl     0x101728b9c               ; 108708: attribute lookup
0x101729500:  add    x0, x20, #0xc0            ; this + 0xC0
0x101729508:  bl     0x1007483b0               ; 39796: ITString store/copy
```

So the “line key” is *definitively* an `ITString` member at `TSLLyricsLine + 0xC0`.

This pairs extremely cleanly with the translation side:

- Translation `<text>` reads attribute `for="..."` into `TSLLyricsTranslationText + 0x70`.
- `TSLLyricsTranslation::ParseXML` inserts `mTranslationMap[ line->mLyricsLineKey ] = line->mLyricsText;`.

So I’m now fully convinced the translation pipeline links to base lyrics lines using:

- Original line key: `itunes:key="..."`
- Translation key ref: `<text for="...">...</text>`

Next:

- Map where the line’s *text content* lives (likely inherited from `TSLLyricsTextElement`, possibly around `+0x60` given constructor patterns in `108462`) so we can be precise about “lyrics text” vs “key” fields.

#### 2026-02-07 23:22-: Translation `<text>` insertion lambda reveals `mLyricsText` offset (`+0x60`) and confirms the map assignment shape in raw code

Local time check:

```sh
date
# Sat Feb  7 23:22:04 EST 2026
```

I wanted to answer the “where does `line->mLyricsText` actually live?” question concretely, and I realized I already had the full disassembly for `TSLLyricsTranslation::ParseXML` (`out/dis_10172d098.s`).

So instead of guessing based on inheritance, I dug into the specific child lambda in that file that:

1) allocates `TSLLyricsTranslationText`,
2) calls `line->ParseXML(...)`,
3) does `mTranslationMap[key] = value`.

Commands:

```sh
# Locate the child lambda body (it’s embedded in the same file as ParseXML)
rg -n \"#0x70\\b|#0x60\\b\" out/dis_10172d098.s | head -200

# Read the hot area around the map insert + copy
sed -n '180,300p' out/dis_10172d098.s
sed -n '260,380p' out/dis_10172d098.s
```

Result: in `___lldb_unnamed_symbol108856` (inside `out/dis_10172d098.s`), right after `line->ParseXML(tNode, tTreeNode)` succeeds, the code literally does:

- `x1 = line + 0x70` as the map key (`mLyricsLineKey`)
- `x1 = line + 0x60` as the mapped value source (`mLyricsText`)
- and it writes into the map node’s value slot at `node + 0x30`

Relevant snippet:

```asm
; out/dis_10172d098.s
; after line->ParseXML(...) succeeds:
0x10172d484: add    x1, x20, #0x70            ; &line->mLyricsLineKey (ITString)
...
0x10172d4a0: bl     0x10171bc58               ; 108469: map find/insert helper (returns node ptr)
0x10172d4a4: add    x0, x0, #0x30             ; &node->mapped_value (ITString)
0x10172d4a8: add    x1, x20, #0x60            ; &line->mLyricsText (ITString)
0x10172d4ac: bl     0x1007484c8               ; 39799: ITString assign/copy
```

So: `TSLLyricsTranslationText::mLyricsText` is at offset `+0x60`, and `TSLLyricsTranslationText::mLyricsLineKey` is at offset `+0x70`.

That strongly implies (and matches the ctor patterns) that the base `TSLLyricsTextElement`’s “text content” `ITString` is at `+0x60`, and translation-text just adds the line-key field at `+0x70`.

Immediate implications:

- For `TSLLyricsLine` (which calls `TSLLyricsTextElement::ParseXML` first), the actual line’s text content is almost certainly the inherited `ITString` at `line + 0x60`.
- The translation pipeline linkage is now fully pinned down with offsets:
  - base line key: `TSLLyricsLine + 0xC0` (from `itunes:key`)
  - translation ref key: `TSLLyricsTranslationText + 0x70` (from `for=`)
  - translated text content: `TSLLyricsTranslationText + 0x60`

#### 2026-02-07 23:30-: Date sanity + major `CreateFromTTML` structure decode (timing type, sections, instrumental gaps, line linking)

Local time check (reconfirming the project’s timeline should still be under `2026-02-07`):

```sh
date
# Sat Feb  7 23:30:25 EST 2026
```

Quick scan for the “wrong date” issue:

```sh
rg -n "^(##|###|####) 2026-02-08" HISTORY.md
# (no matches)
```

So the only remaining `2026-02-08` mentions are in my own logged commands, not as section headers. This aligns with local time still being Feb 7.

Now back to lyrics.

I focused on `TSLLyricsSongInfo::CreateFromTTML` (`___lldb_unnamed_symbol108718` at `0x101729d98`) and tried to answer the next big structural questions:

- What is `songInfo + 0x18` actually representing?
- What *exactly* is stored at `songInfo + 0x78` and how does it relate to instrumental gaps?
- How are sections/lines wired together after parsing?

##### `songInfo + 0x18` is a “timing granularity” enum (likely 1/2/3 = none/line/word)

I already knew `songInfo + 0x18` starts as `1` (constructor behavior), and I’d seen a consumer (`108914`) storing it into some upstream object. I wanted a firm meaning.

In `CreateFromTTML`, there’s a loop that walks the parsed line list and inspects timings on:

1) the line itself (start/end), and
2) the line’s word list (each word start/end).

If it sees any word timings, it forces `songInfo + 0x18 = 3`. Otherwise, if it sees any line timings, it forces `songInfo + 0x18 = 2`. If neither exists, it remains `1`.

Evidence (from `out/dis_101729d98.s`):

```asm
; constants:
0x101729e8c: mov w23, #0x2          ; candidate: line-timed
0x101729e90: mov w24, #0x3          ; candidate: word-timed
0x101729e94: mov w25, #0x1          ; default/none

; per-line: x26 = TSLLyricsLine*
0x101729ea8: ldp x27, x28, [x26, #0xa8]    ; line->mWords vector (begin/end) @ +0xA8

; per-word: x8 = TSLLyricsWord*
0x101729ec4: ldr d0, [x8, #0x40]            ; word start?
0x101729ed0: ldr d0, [x8, #0x48]            ; word end?
0x101729eec: ldr x8, [sp, #0x40]            ; songInfo ptr
0x101729ef0: str w24, [x8, #0x18]           ; songInfo->timingType = 3 (word timed)

; line-level timings:
0x101729f0c: ldr d0, [x26, #0x40]            ; line start?
0x101729f18: ldr d0, [x26, #0x48]            ; line end?
0x101729f24: str w23, [x8, #0x18]            ; songInfo->timingType = 2 (line timed)
```

This is a nice clean story:

- `timingType == 1`: no start/end times anywhere (static/plain lyrics)
- `timingType == 2`: lines have start/end but words do not (line-synced)
- `timingType == 3`: words have start/end (word-synced)

I’m still calling it an “inferred enum” until I see a log string or a switch table on the values, but the evidence is strong.

##### `songInfo + 0x78` is a `vector<shared_ptr<TSLLyricsSection>>` and `TSLLyricsSection + 0x60` is a “section type”

I already suspected `songInfo + 0x78` was “sections” because the plain-text flattener iterates it. `CreateFromTTML` makes this *very* concrete.

If `songInfo->timingType != 1`, `CreateFromTTML` iterates the sections vector and looks for gaps between adjacent sections. If it finds a large gap, it inserts a new “instrumental” section in-between.

Evidence (from `out/dis_101729d98.s`):

```asm
0x101729fa0: ldr w8, [x20, #0x18]    ; songInfo->timingType
0x101729fa4: cmp w8, #0x1
0x101729fa8: b.eq ...                ; no timed lyrics => skip instrumental-section insertion

0x101729fb0: ldp x8, x9, [x22, #0x78]!  ; section vector begin/end (shared_ptr pairs, 16B each)

; section loop: x28 = section*, x21 = control block
0x101729ff0: ldr w8, [x28, #0x60]    ; section->type
0x101729ff4: cmp w8, #0x8
0x101729ff8: b.eq ...                ; already instrumental => skip gap logic

; gap = section->start - prevEnd
0x101729ffc: ldr d0, [x28, #0x40]    ; section start time
0x10172a000: fsub d0, d0, d9         ; d9 tracks prevEnd
0x10172a004: fcmp d0, d8             ; d8 = 7.0
0x10172a008: b.le ...                ; small gap => no insertion

; allocate TSLLyricsSection (size 0x98) and mark it as instrumental (type=8)
0x10172a00c: mov w0, #0x98
0x10172a024: bl  0x10171b690         ; 108457: TSLLyricsSection ctor
0x10172a038: str d9, [x10, #0x40]    ; new->start = prevEnd
0x10172a040: str d0, [x10, #0x48]    ; new->end   = section->start
0x10172a044: str w26, [x10, #0x60]   ; new->type  = 8
```

Also interesting: the “end-of-song” missing instrumental gap threshold is *much* larger than 7 seconds:

```asm
0x10172a360: ldr d0, [songInfo, #0x20]   ; looks like song duration
0x10172a364: fsub d0, d0, d9             ; trailingGap = duration - lastSectionEnd
0x10172a368: fmov d1, #120.0
0x10172a370: fcmp d0, d1
0x10172a374: b.le ...                    ; <= 120s => don’t insert end instrumental section
```

So:

- in-between gaps: insert if gap > 7 seconds
- trailing gap: insert if gap > 120 seconds

I’m guessing this is to avoid painting common “tail silence” as instrumental unless it’s extreme.

##### `TSLLyricsSection::ParseXML` behavior: section has `itunes:songPart`, contains `<p>` lines, and forces empty sections to type=8

While chasing section semantics, I noticed that my earlier `out/dis_1017294a4.s` dump (which started at `TSLLyricsLine::ParseXML`) contains additional adjacent functions. One of them (`___lldb_unnamed_symbol108716` at `0x101729a0c`) is clearly section parsing.

It reads `itunes:songPart` into a member at `this + 0x8` via `108440`, then enumerates its children and parses lines. It also has a strong policy:

- If a section has **no lines** and its type is not already `8`, it logs a warning and forces `type = 8` (instrumental).

Evidence (from `out/dis_1017294a4.s`):

```asm
; read itunes:songPart into section + 0x8
0x101729a48: adrp x1, ... ; "itunes:songPart"
0x101729a70: bl   0x101719d28       ; 108440: store/copy attribute into section member
0x101729a88: add  x1, x19, #0x8
0x101729a8c: bl   0x10092d920       ; 49895 (looks like timing parse helper used elsewhere too)

; after enumerating child lines:
0x101729ae8: ldp  x9, x8, [x19, #0x80]  ; section->mLines vector begin/end @ +0x80
0x101729aec: cmp  x8, x9               ; empty?
0x101729af4: ldr  w8, [x19, #0x60]     ; section->type
0x101729af8: cmp  w8, #0x8
...
0x101729b38: ... "WARNING: Detected lyrics section with no lines; forcing to instrumental"
0x101729b50: mov  w8, #0x8
0x101729b54: str  w8, [x19, #0x60]     ; section->type = 8
```

The *really* juicy part is the huge assert string inside this function (not included verbatim here), which explicitly describes the child enumeration:

- If child is `kXMLElementLine`:
  - allocate `TSLLyricsLine`
  - `line->ParseXML(...)`
  - drop empty `line->mLyricsText.Trim().IsEmpty()` (logs “Dropping empty line, time span %g - %g”)
  - else:
    - `line->mParentSection = thisRef`
    - `line->mLineIndex = line->mOriginalLineIndex = lyricsLineList.size()`
    - `mLines.push_back(line)`
    - `lyricsLineList.push_back(line)`

So at a data-model level, the “section vs songInfo lines vector” split is:

- `TSLLyricsSection::mLines`: per-section list of lines
- `TSLLyricsSongInfo::mLines`: global flattened list across all sections

##### `TSLLyricsSongInfo::SetLines`-like function (`108429`) sets `line + 0x78` index and stores a weak “next line” link at `line + 0x98`

I disassembled `___lldb_unnamed_symbol108429` at `0x101718e98` into `out/dis_101718e98.s` to see what it does when `CreateFromTTML` calls it with the stack `lyricsLineList` vector.

The very first thing it does is compare `x1` with `this + 0x60`, which makes it almost certainly “assign/move lines vector into songInfo”:

```asm
0x101718eb4: add x0, x0, #0x60
0x101718eb8: cmp x0, x1
```

Then it walks `songInfo + 0x60` and for each `TSLLyricsLine`:

1) stores a monotonically increasing index into `line + 0x78`,
2) stores a *weak* reference to the “next” line into `line + 0x98` (object+control) and releases the prior weak control at `line + 0xA0`.

Evidence (from `out/dis_101718e98.s`):

```asm
; i -> line->mLineIndex?
0x101718f2c: str x22, [x10, #0x78]

; line->mNextLine (weak) = next line shared_ptr
0x101718f48: ldp x9, x8, [x8, #0x10]   ; load next line shared_ptr (obj, ctrl)
0x101718f50: add x11, x8, #0x10
0x101718f54: ldadd x23, x11, [x11]     ; inc weak count (ctrl + 0x10)
0x101718f5c: stp x9, x8, [x10, #0x98]  ; store into line + 0x98
0x101718f64: bl  __release_weak        ; release old weak ctrl at line + 0xA0

; last line => nextLine weak ptr cleared
0x101718f94: stp xzr, xzr, [x10, #0x98]
```

This is awesome because it gives me two new stable offsets for `TSLLyricsLine`:

- `TSLLyricsLine + 0x78`: line index (size_t)
- `TSLLyricsLine + 0x98`: weak next-line storage (two pointers), with the old ctrl pointer at `+0xA0`

##### Per-section post-processing (`108441`) computes average line duration into `section + 0x78`

In `CreateFromTTML`, after calling `108429`, it iterates sections and calls `___lldb_unnamed_symbol108441` at `0x101719f5c`.

Disassembling that into `out/dis_101719f5c.s` shows it computes an average line duration:

- It only runs if `section + 0x78` is currently 0.
- It iterates `section->mLines` vector at `section + 0x80` and for each line, adds `(line->end - line->start)`.
- It divides by line count and stores back to `section + 0x78`.

Evidence (from `out/dis_101719f5c.s`):

```asm
0x101719f5c: ldr d0, [x0, #0x78]
0x101719f60: fcmp d0, #0.0
0x101719f64: b.ne ... ; already computed

; iterate section + 0x80 vector of lines
0x101719fb0: ldp d1, d0, [x8, #0x40]   ; line start/end
0x101719fb4: fsub d9, d0, d1           ; duration
0x101719fc8: fadd d8, d8, d9           ; accumulate

; avg = total / count
0x101719fe8: fdiv d0, d8, d0
0x101719fec: str  d0, [x19, #0x78]     ; store avg
```

So `TSLLyricsSection + 0x78` is (very likely) `averageLineDuration` (double).

##### New artifacts created under `out/` (gitignored)

Commands I ran:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" -o "disassemble -s 0x101718e98 -c 650 -b -r" -o "quit" > out/dis_101718e98.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" -o "disassemble -s 0x101719f5c -c 650 -b -r" -o "quit" > out/dis_101719f5c.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" -o "disassemble -s 0x10171b690 -c 450 -b -r" -o "quit" > out/dis_10171b690.s
```

Files:

- `out/dis_101718e98.s` (`108429`): line vector assignment + line linking
- `out/dis_101719f5c.s` (`108441`): compute avg line duration for a section
- `out/dis_10171b690.s` (`108457`): section constructor confirms `type` is at `+0x60` and lines vector storage starts at `+0x80`

Next:

- I still need to locate *where* translations are applied at render time: something has to look at `songInfo + 0x90` (language -> (lineKey -> text)) and choose which text is displayed for each line.
- I also want to extract the full `TSLLyricsSection::ParseXML` child lambda code (not just the assert string) to pin down the exact offsets for:
  - `line->mParentSection`
  - `line->mOriginalLineIndex`
  - the section’s “songPart” field and the “section type” meaning beyond `8`.

#### 2026-02-07 23:40-23:47: Trying to find translation *rendering* / UI integration (no solid hit yet)

Local time check:

```sh
date
# Sat Feb  7 23:47:26 EST 2026
```

I took a first swing at “where do translations get applied?” by looking for any UI/controller code that seems lyrics-specific, and by searching for likely class names.

##### Symbol scan: only one `TSLLyrics*` ObjC class is in the symbol table

Command:

```sh
nm -m /System/Applications/Music.app/Contents/MacOS/Music | rg "TSLLyrics" | head -200
```

Result:

- The symbol table only surfaces `TSLLyricsControllerWrapper` (ObjC) and its methods like `loadView`, `viewWillAppear`, etc.
- No obvious “translation” or “transliteration” class names appear in symbols.

##### Static string scan: there *is* a C++ `TSLLyricsViewController` name in the binary

This came from a quick TSLLyrics-focused string sample:

```sh
/usr/bin/strings -a -n 4 /System/Applications/Music.app/Contents/MacOS/Music | rg "TSLLyrics" | head -500 | sort -u | head -200
```

Notable lines included:

- `TSLLyricsViewController::ClearHighlight`
- `TSLLyricsViewController::RollOutDelay`

I tried to use these as “anchors” to find related code.

##### `otool` gives VM addresses for those method-name strings, but xrefs are misleading

Commands:

```sh
otool -v -s __TEXT __cstring /System/Applications/Music.app/Contents/MacOS/Music | rg "TSLLyricsViewController::(ClearHighlight|RollOutDelay)"
python3 scripts/find_arm64_adrp_add_xrefs.py --target 0x101aa79d4 --window 12
python3 scripts/find_arm64_adrp_add_xrefs.py --target 0x101aa781b --window 12
```

Output:

- `0x101aa781b`: `TSLLyricsViewController::RollOutDelay`
- `0x101aa79d4`: `TSLLyricsViewController::ClearHighlight`

But the ADRP+ADD xrefs landed at:

- `0x101728AD8` / `0x101728AEC` / `0x101728AF0`

…which is squarely inside the TSLLyrics XML parsing “utility” region (near `108708` attribute lookup etc), not in some UI controller.

Disassembling around there (`out/dis_101728a80_misc.s`) shows those strings are loaded inside `___lldb_unnamed_symbol108706`:

```asm
0x101728ad8: adrp x0, ... ; "TSLLyricsViewController::RollOutDelay"
0x101728ae0: bl   0x1006eb398
...
0x101728af0: add  x0, x0, #0x9d4  ; "TSLLyricsViewController::ClearHighlight"
0x101728b08: b    0x1006eb398
```

So those strings are being used by some helper function (maybe building a couple of static `ITString`s?) and *not* directly as log-context from the view controller’s code. In other words: this didn’t help me find the rendering path.

##### Disassembled `TSLLyricsControllerWrapper` methods anyway (no translation clues)

I dumped a couple of wrapper functions just to see if they touch translation state:

```sh
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" -o "disassemble -s 0x10143d50c -c 600 -b -r" -o "quit" > out/dis_10143d50c_TSLLyricsControllerWrapper_loadView.s
lldb -o "target create '/System/Applications/Music.app/Contents/MacOS/Music'" -o "disassemble -s 0x10143d84c -c 220 -b -r" -o "quit" > out/dis_10143d84c_TSLLyricsControllerWrapper_lyricsPlusPlusView.s
```

These are mostly Objective-C message sends and view wiring; nothing obvious about `TSLLyricsSongInfo + 0x90` or `line + 0xC0` (line key) yet.

Net: I still don’t have the “translation rendering” call chain pinned. Next I think I should:

- look for *any* code that touches **both** `line + 0xC0` (line key) and `songInfo + 0x90` (translation map) in the same function, or
- find a function that enumerates translation languages from `songInfo->mTranslationsMap` and see who calls it.
