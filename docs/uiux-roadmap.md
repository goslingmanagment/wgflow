# wgflow Panel — UI/UX Roadmap

*Lead design + eng synthesis. Opinionated. Built on the actual tree (`web.go`, `webui/src/...`), not assumptions. Generated 2026-06-27 from a multi-agent pass (3 codebase readers → 11 design themes × 38 proposals → adversarial feasibility check → synthesis).*

> Reality check before we start: two of the listed "known issues" are **already fixed** in the current code and should be struck from the backlog. DNS rcodes are correctly mapped by `dnsRcodeName()` in `format.js:63` and wired in `Dns.svelte:56` and `ClientDetail.svelte:88` (no more blanket "NXDOMAIN"). Client/target search is already case-insensitive — `Clients.svelte:27-28` lowercases both sides, as do `web.go:564,576` (Traffic) and `web.go:691,711` (TLS). Spend 15 minutes confirming, then close them. The throughput axis, 6-8s client detail, thin categorizer, and the three fake-green status chips are all genuinely broken.

---

## 0. Owner-approved revision (2026-06-27) — supersedes §8 ordering

Owner reviewed and approved the product thesis (a fast "who/which device/background-or-not + ready Срез" pulse, not a network dashboard). The decided build order **supersedes §8**:

1. **Quick wins (§3)** — as written; treat as trust/correctness, not cosmetics.
2. **Minimal classifier + health (ship together).** Return a **rich contract**, not a bare enum:
   `status` (`active|likely-background|silent`), `confidence`, `reasons[]`, `logger_ok`, `last_significant_at`, `evidence{}`.
   UI may then say "вероятно активна" and never fake knowledge of human intent. `last_significant_at` folds in the dual last-seen — put `last_any_at` (last ping) alongside it in `evidence` so "когда последний раз онлайн" separates real use from a push.
3. **`/api/snapshot` + copyable Срез** — the signature feature. **Gate it:** the Срез/copy path must refuse to emit a confident verdict when `logger_ok=false` (never copy confident nonsense during an outage). Build only after step 2 exists.
4. **`from/to` + per-minute reconstruction** — raised ABOVE the big Clients redesign. This is core to "с 02:05 / ласт 10 / когда проснулась".
5. **Alias/person grouping via `clients.yaml`** — a config mapping person → devices (+ display names, optional `kind: phone|laptop` override), NOT `name.split('-')[0]` (which breaks on `mom`, odd names, hyphens). The alias config is the prerequisite; pretty grouping is downstream of it, and the `kind` override also de-risks the classifier's suffix guess.
6. **Perf polish** — gated by a **performance budget** (below); measure first, add complexity only if a budget is missed.
7. **Categorization v2** — last; rules expand, never assert intent.

**De-scoped / softened from the body below:**
- **Big person-grouped Clients redesign (§5)** → after evidence + Срез + alias config, not first.
- **Progressive ClientDetail `?part=` split (§4)** → don't commit yet. Measure server latency after snapshot + cache; a fast-path endpoint + short cache may be enough, and `?part=summary|targets|day` complicates the API contract.
- **10s memoization (§4)** → too coarse for "last 5 min". Replace with a **flush-generation cache**: key it on `stats.json` `last_flush_at` (the rollup only changes every 30s, `-flush` default). Responses are then instant between flushes and fresh immediately after one — no arbitrary TTL. Include `cached_at` in the payload.
- **`kind` = music/push/open-socket (§4)** → weak heuristic only. Render "Yandex Music / stream-like domains", never "слушает музыку".
- **Token auth / sessions / Access console (§7)** → not now. Basic auth + bind `127.0.0.1` + SSH/WireGuard tunnel is fine; just add a loud warning banner when `--auth-password` is empty.

**Added to the plan:**
- **Classifier fixture tests.** Table-driven tests over synthetic flow/category/timing fixtures so the rules stay falsifiable and don't rot into magic constants. (`main_test.go` already establishes the fixture pattern.)
- **Retention.** JSONL rotation already exists — `wgflow.logrotate` (`daily, rotate 14, compress, maxsize 100M, copytruncate`) ⇒ ~14-day raw retention. **The real gap is `rollup.db`:** no prune anywhere in the Go (grep clean), so bbolt grows unbounded (already ~54MB). Add a rollup retention/prune (e.g. drop minute buckets older than N days) and deliberately set the raw-JSONL keep window.
- **Performance budget (gates step 6):** `/api/snapshot?since=5m` < 300ms · `/api/clients` < 500ms · ClientDetail summary < 300ms.

**Constraint surfaced for `from/to`:** `rollup.db` carries bytes/minutes far back (until pruned), but per-minute **domains** (TLS/DNS) come from JSONL reverse-scans, which logrotate compresses/rotates daily. So byte-level reconstruction reaches back as far as rollup retention, while per-minute **domain** lookups only reach as far as un-rotated JSONL (today + a few days; reading rotated `.gz` is extra work). This reinforces "load domains lazily only for flagged minutes" and bounds how far "когда проснулась" can name domains versus just show volume.

> The sections below (§1–§8) are the full reference design. Where §0 differs, §0 wins.

---

## 1. The core reframe

The panel was built as a **generic 8-section analytics dashboard** (equal-weight nav, English byte tables, fetch-once screens). But the owner uses it as a **live surveillance command board**: he asks "who / which device / active-or-background?" in 5-30 minute bursts, dozens of times a day, then wants a **copy-ready MSK "Срез" verdict paragraph** to paste into chat. Every screen today makes him do the synthesis in his head and lies to him with a hardcoded green dot while doing it.

**The single biggest leverage change:** build ONE server-side `active / likely-background / silent` **classifier**, expose it on `/api/clients` and `/api/clients/{name}`, and let it drive (a) a person-grouped verdict board on the Clients home screen and (b) a one-click **Срез generator**. Everything else is plumbing in service of that. Recompose existing screens — do **not** touch the 8-icon rail.

---

## 2. Signature feature — The Verdict Engine + one-click "Срез"

This is the product. The classifier is the brain; the Срез is its highest-value output. They ship together because a copy-pasteable paragraph about real people is the highest-stakes honesty surface in the whole app, so the verdict and the caveat must be defined in exactly one place.

**Engine (`classify()` in Go, one definition).** Inputs are all cheap and already in the rollup path:
- per-minute `series` (binary `flow_client_minute_v1`, already powering sparklines) → count of `>1MB` and `>100KB` minutes, last non-zero minute;
- `cats[]` (already returned) → background-signature detection;
- `last_tls` / `last_dns` timestamps → freshness (near-free: `lastSitesByClient` at `web.go:323` already reverse-scans `tls.jsonl`; capture `rec.TS` and add a parallel `dns.jsonl` pass);
- `device_kind` from the WG-peer name suffix (`-iphone/-ipad`→phone, `-macbook/-mac/-pc`→laptop) — free;
- `logger_ok` from `stats.json` `last_flush_at` freshness — so **SILENT can never be confused with a dead logger**.

Rules (tunable, heuristic, always rendered with `· inferred`):
- **SILENT** = 0 bytes in window AND `logger_ok`.
- **ACTIVE** = a run of `≥2` minutes over 1MB, OR tens of MB, OR fresh TLS/DNS (<~3 min) to a non-background category; weighted up for phones.
- **LIKELY-BACKGROUND** = small volume, categories only in {apple, dns} or known open-socket hosts (Fansly `wsv3`/`chatws`, Telegram API), no fresh TLS/DNS; weighted toward laptops.

**Срез drawer** — a coral "Срез" button in the Clients header opens a right-side drawer, calls one fast `/api/snapshot?since=` (binary buckets + the recent-sites scan, deliberately avoiding the slow `flow_minute_v1` JSON path), groups devices into people client-side, and assembles the verbatim Russian block. MSK via `Intl.DateTimeFormat(timeZone:'Europe/Moscow')`. The `[copy]` button copies plain text **with the caveat line included inside the copied string**, never just in the drawer chrome. QUIC/IP-only targets render `без имени (QUIC)`, never a faked domain.

```
┌ Срез · последние 5 мин ───────────────── [copy] [↻] ┐
│ Срез на 12:29 МСК, последние 5 минут.               │
│                                                     │
│ diana   ● активна (iPhone)              47.8 MB     │
│   iphone  47.8 MB · Yandex Music/стрим             │
│     api.music.yandex.net · avatars.yandex.net ·     │
│     yandex.ru                                       │
│   macbook 0 · тишина                               │
│   Вывод: активна с iPhone, MacBook не участвует.    │
│ ─────────────────────────────────────────────────  │
│ mom     ◐ фон (MacBook)                  0.3 MB    │
│   macbook 0.3 MB · только apple push/OCSP + DNS    │
│     gateway.icloud.com · ocsp.apple.com           │
│   Вывод: вероятно фон (открытый ноут), не человек. │
│ ─────────────────────────────────────────────────  │
│ anya    ○ тишина                          0 B      │
│   iphone 0 · ни TLS, ни DNS в окне                 │
│   Вывод: тишина (логгер исправен, 0 байт).         │
│                                                     │
│ ⚠ inferred из метаданных. HTTPS не виден; QUIC даёт │
│   IP без имени; «проснулась» недоказуемо — только   │
│   первый заметный след. Байты ~94–95% (GSO/GRO).    │
└─────────────────────────────────────────────────────┘
```

Hard rules baked in: verdict text always carries `(inferred)`/`вероятно`; never "проснулась/woke up", only "первый заметный след"; the caveat footer is non-removable and travels **inside** the copied text; `тишина` only renders when `logger_ok`.

---

## 3. Quick wins (ship this week)

S-effort, high-impact, mostly frontend. Do all of these first — several are correctness bugs, not features.

- **Pin all times to MSK.** Add `fmtMSK(ts)` / `hhmmMSK(ts)` to `format.js` using `Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow'})`; route `Chart.fmtT` (`Chart.svelte:15-17`, currently `toLocaleTimeString('en-GB')`), `Dns.hhmmss` (`Dns.svelte:31-33`), and ClientDetail recents through it. Add a live MSK wall-clock next to `Win` in the header. **Backend bug:** `clientDayTimeline` buckets by the server's local `time.Unix(...).Hour()` (`web.go:510,547`) — load `Europe/Moscow` once and bucket through it so the host TZ stops leaking. Moscow has no DST since 2014, but use the tz database, not a hardcoded +3. *Why: every core question is "at HH:MM MSK"; the Срез is worthless if the clock is the viewer's phone TZ.*

- **One honest health signal; fix the stale-forever pill.** `App.svelte:42-49` opens the SSE but has **no `es.onerror`** and never resets `live` on drop — a dead capture shows the last `mbit` forever. Add `onerror`/reconnect, stamp `lastEventAt`, and a 1s ticker deriving LIVE / STALE / DOWN from `updated_at` + `last_flush_at` freshness (both already on `RuntimeStats`, `main.go:36`). Promote to the store and **delete all three fake-green literals** (Clients pill `Clients.svelte:36`, ClientDetail `active now` chip `ClientDetail.svelte:45`, System `healthy`) — bind them to one verdict so the UI can never look healthier than the logger. *Why: a monitoring tool that can't tell "silent" from "I crashed" is dangerous.*

- **Fix the throughput time axis.** `ClientDetail.svelte:27-33` synthesizes `t = Date.now()/1000 - (n-1-i)*60`, anchoring the x-axis to the **browser** clock so it drifts from the server window. The `series` is already zero-filled/contiguous server-side; just return real minute timestamps. Smallest fix: add `series_start_minute` (or change `series` to `[{t,down,up}]`) on `/api/clients/{name}` and build points from `(startMinute+i)*60`. *Why: "reconstruct after a cutoff" needs an axis that matches the clock he quotes.*

- **Honest targets in ClientDetail.** In `top_targets` (`ClientDetail.svelte:73-75`), when `net.ParseIP(target)!=nil` render `77.88.21.0 · no hostname (QUIC)` instead of a bare IP that reads like missing data; tag `category=apple` rows as `Apple push` (muted). Add a right-aligned footnote `~94–95% of bytes · packets approximate (GSO/GRO)` on the targets and KPI cards. Pure presentation; optional `is_ip`/`resolved` bool later to avoid the regex. *Why: this is the honesty layer the whole verdict rests on — highest value-per-effort.*

- **Palette fix.** In `CAT_COLORS` (`format.js:80`): `apple #9aa7b4` and `other #6b7785` are near-identical greys, and `yandex #eb6834` collides with the coral brand accent. Give apple a distinct slate-blue and shift yandex off the coral hue. Trivial edit that unblocks Mix/Donut/DayTimeline legibility for the active-vs-background read. *Why: free, and the verdict UI depends on these dots being distinguishable.*

- **Close the two already-fixed "known issues."** Verify DNS rcode labels (`format.js:63`, already correct for all codes) and case-insensitive search (`Clients.svelte:27-28`, `web.go:564/576/691/711`), then strike them from the backlog. *Why: don't rebuild working code.*

---

## 4. Bigger bets (worth it)

M/L items needing new endpoints or aggregation. Sequenced so the cheap, high-impact ones land first.

- **The verdict engine (the §2 brain), server-side.** Add `classify(c, devKind)` + `deviceKind()` in `web.go`; extend `apiClient` (`web.go:178`) with `verdict`, `verdict_reason`, `device_kind`, `min_over_1mb`, `last_tls`, `last_dns`, plus top-level `logger_ok`. `last_tls` is nearly free (capture `rec.TS` in `lastSitesByClient`); `last_dns` is one parallel `dns.jsonl` reverse-scan. **Unlocks:** every "what is X doing / iPhone or MacBook?" question, and feeds both the board and the Срез. *Keep the rules heuristic-labeled; the background reason is the weakest link — expose the firing rule in a tooltip so it's falsifiable, never asserted.*

- **`/api/clients` 10s memoization + progressive ClientDetail.** `aggregateClients` (`web.go:289`) does a full `flow_minute_v1` JSON-unmarshal scan and `seriesByClient` (`web.go:343`) re-opens bbolt separately — 15s polling across tabs would hammer the 54MB scan. Memoize the aggregate ~10s keyed by `since` (~20 lines). For the 6-8s detail: split `/api/clients/{name}` into `?part=summary|targets|day` so the cheap parts (binary series, jsonl tails, verdict) paint in <300ms while `top_targets` and the day timeline stream behind skeletons. **Ensure `flow_client_category_minute_v1` (the index bucket) exists** so `clientDayTimeline` (`web.go:486`) never falls back to the full 24h JSON scan at `web.go:489-518`. **Unlocks:** a pollable live board and a detail page that feels instant.

- **`/api/snapshot?clients=&since=` (binary-bucket fast path).** One request returns per-client `{total, down, up, minutes_over_100k, minutes_over_1mb, cats[], recent_sites[], verdict, device_kind}` read from `flow_client_minute_v1` + `flow_client_category_minute_v1` + the extended recent-sites scan. Powers the Срез drawer and the watch matrix without the slow `aggregateFromRollup` path. **Unlocks:** rapid burst polling for the §2 Срез.

- **Person grouping on Clients (frontend only).** Group rows by `name.split('-')[0]`; person header = serif name + aggregate verdict ("ACTIVE (iPhone)") + summed volume + merged Mix; device sub-rows keep their own badge + phone/laptop glyph. Auto-expand when devices disagree (phone active, laptop silent — the interesting case). A `person | device` toggle (coral, matching the existing sort buttons), choice persisted in the store. Zero backend. **Unlocks:** "compare the people" and the owner's real person→devices mental model. *Handle unmapped/odd names (`mom`) gracefully — a missing `-` must not orphan a device.*

- **Cutoff anchor + per-minute reconstruction.** Add `parseRange(from,to)` beside `parseSince` (`web.go:118`); accept `?from=&to=` on the aggregators (they all already compute `cutoff := now.Add(-d)` — a one-line swap). Add a per-minute ribbon to ClientDetail for windows ≤30m driven by the cheap binary bucket: one row per MSK minute with bar, MB, `⚑>100KB`/`⚑>1MB` flags, dominant category dot, silent rows shown explicitly, footer `first significant trace HH:MM МСК · N flagged`. **Unlocks:** the literal "after 02:05 MSK, flag >100KB/>1MB minutes" workflow. *Load per-minute domains lazily per flagged minute — see DON'T.*

- **Categorization rules v2 + palette (extends the quick-win palette fix).** Expand `categorize()` (`main.go:813`): add vk, netflix, spotify, microsoft, generic-CDN; honest best-effort Twitch (label inferred, AWS fallback). Optional orthogonal `kind` (media/messaging/push) for the hostname-visible fraction only. **Unlocks:** shrinks the "other" bucket that swallows Twitch/AWS/gaming, and sharpens the verdict's category signal. *Applies live + to future rollups, NOT retroactively to frozen rows; `kind` is blank for IP-only QUIC, so never headline "apple = 88% push."*

---

## 5. Redesigned Clients (hero) + ClientDetail

Atlas × Console preserved: coral `#e06a3f` = ACTIVE + sparkline; warn amber = LIKELY-BG; muted grey = SILENT (deliberately not danger-red); serif person names; mono tabular numerals; categorical `CAT_COLORS` for the Mix; verdict shown as a dot+badge (never a row tint, to dodge the yandex/coral collision).

**Clients — person-grouped verdict board, auto-refreshing:**

```
Clients   ◀ 5m  [10m]  30m ▶     ● updated 4s ago   ✓ healthy   [Срез]
group: [person] device                                       🔍 find
─────────────────────────────────────────────────────────────────────
Person · doing now              net      rate     volume   mix
─────────────────────────────────────────────────────────────────────
▼ Diana            ● ACTIVE (iPhone)            48.3 MB  ▓▓▓░░ yandex
    📱 diana-iphone ● ACTIVE ▁▃█▇█▆ 3.1 Mbit/s  47.8 MB → api.music.yandex.net
      inf · 14 min >1MB, fresh TLS (yandex)
    💻 diana-macbook ◦ SILENT ──────  0 Mbit/s     0 B  → 0 B, logger healthy
▶ Mom              ● BG ~                         0.4 MB ▒▒░░░ apple
    📱 mom-iphone   ● BG ~  ▁_▁__▁                0.4 MB → push.apple.com · OCSP only
▶ Anya             ● ACTIVE (MacBook)            11.3 MB ▓▓▒░░ meta/other
    💻 anya-macbook ● ACTIVE ▂▅▆▅▇▄              11.3 MB → 17.248.x.x no hostname (QUIC)
▶ Alina            ◦ SILENT                        0 B  ····· —
─────────────────────────────────────────────────────────────────────
4 people · 5 devices · last 10m · classification inferred ⓘ
● active  ● background  ◦ silent — badges are inferred, not proof

── if flush stalls ──
⚠ logger last flushed 4m12s ago — SILENCE NOT CONFIRMED. Check System.
  0-byte rows below may be an outage, not real quiet.
```

**ClientDetail — verdict header + "Right now" + per-minute ribbon (progressive paint):**

```
‹ Clients
diana-iphone                         [ ACTIVE · inferred ]      ← 180ms
iPhone · last significant trace 12:27 МСК (2 min ago)

[5m][10m][15m][30m][6h][Day]                       ⧉ Copy срез

┌ Right now ───────────────────── 12:29:14 МСК ─┐  Recent sites (TLS)
│ 3.1 Mbit/s ▁▂▅█▆   hitting now:               │  🔒 api.music…  12s
│ api.music.yandex.net · avatars.yandex.net     │  🔒 yandex.ru   40s
└───────────────────────────────────────────────┘  🔒 push.apple  2m (bg)

Rate·5m      Download    Upload     Top category
0.64 Mbit/s  47.8 MB     2.1 MB     ● yandex

VERDICT  Active from this device — sustained Yandex Music stream
(5/5 min > 1 MB, fresh TLS+DNS). Inferred from logs; can't prove a human acted.

┌ Per-minute · last 30m ──────────── ↓down ↑up ─┐  ┌ Top targets ──── ~94–95% (GSO/GRO)
│ 12:24 ▃  340 KB  ⚑>100KB  ● yandex            │  │ api.music.yandex.net  ●yandex 31.2MB
│ 12:25 █  2.4 MB  ⚑>1MB    ● yandex            │  │ 77.88.21.0 · no hostname (QUIC) ⓘ
│ 12:26 █  3.1 MB  ⚑>1MB    ● yandex            │  │ 17.57.144.22 · Apple push      88KB
│ 12:28 ▂   88 KB           ● apple             │  └ (heavy scan streams in behind skeleton)
│ 12:29 ░  silent                               │
│ first significant trace 12:24 МСК · 4 flagged │
└───────────────────────────────────────────────┘
```

---

## 6. Honesty & accuracy in the UI

This is non-negotiable — it is what makes the verdicts worth quoting. Make honesty **structural, not a footnote**:

- **Every classification carries `· inferred`** and a hover/tooltip stating the exact rule that fired + the standing caveat ("logs cannot prove a human acted; HTTPS content invisible"). The caveat travels **inside** copied/exported text, not just the chrome.
- **SILENT is gated on logger health.** 0 bytes only reads as `SILENT` when `last_flush_at` is recent and drops are flat; otherwise a danger banner: "SILENCE NOT CONFIRMED — logger may be down." Never brand an outage as quiet.
- **Bare-IP / QUIC targets render `no hostname (QUIC)` / `без имени (QUIC)`** — never a fabricated or stale-cache domain. Detect via `net.ParseIP`.
- **Byte volumes are qualified `~94–95% (GSO/GRO)`** wherever they appear; the 100KB flag sits near that error floor, so flags are `≈`, not exact. Packet counts are never surfaced as wire-accurate.
- **"woke up" is forbidden** — only "first/last significant trace."
- **Absence of DNS/TLS ≠ idle** (DoH/cached/ECH). The Срез must not read an empty domain list as silence when bytes exist.
- **MacBook background is expected** — laptop ACTIVE is rendered softer than phone ACTIVE; `apple`-only can hide real iCloud use, so the reason line stays hedged.
- **MSK label is rendering-only** and fixes the clock, not the byte error or the unprovability of human action — don't let a precise timestamp imply precise volume or proven intent.

---

## 7. Explicitly DON'T do

- **No persistent read-only bbolt handle on the web server.** It would contend with the separate capture process's file lock — a data-loss bug, not a perf regression. Get the latency win from the part-split + 10s memo + ensuring the category index bucket exists instead.
- **No per-minute domain join over a wide cutoff window.** The per-minute *bytes/flags* are cheap (binary bucket); the per-minute *top domain* forces the slow `flow_minute_v1` JSON scan + jsonl join and re-creates the 6-8s stall (or hits the 5s read timeout). Cap the reconstruction window and load domains lazily per **flagged** minute only.
- **No `/api/health` with `systemctl` exec.** The stats-freshness half is redundant with the SSE verdict; the only unique bit (process liveness) is "unknown (not permitted)" in prod and absent on the Mac dev host. Thin payoff, real attack surface. Defer.
- **No token-auth / multi-device session store / Access console yet.** Real but orthogonal to his daily questions; it's a separate hardening epic. Keep Basic for now; only add the loud `UNAUTHENTICATED` banner if `--auth-password` is empty (cheap, server-authoritative).
- **No new nav items.** Everything recomposes Clients / ClientDetail / Reports. The 8-icon rail stays at 8.
- **Don't overclaim sub-categories or `kind`.** "стрим/Music", "push only", "open socket", "no new connections" are unprovable from metadata and only cover the hostname-visible sliver. Render category share, not asserted intent. Drop the DoH-suspect *count* (it reads authoritative but is a guess).
- **Don't ship the verdict without the health cross-check and the inferred label** — it's the difference between an honest tool and a confident lie about real people.

---

## 8. Suggested sequencing

1. **Quick wins (§3) as one PR:** MSK helpers + `clientDayTimeline` TZ fix; honest health pill + SSE `onerror` fix; throughput-axis timestamp fix; `no hostname (QUIC)` + GSO footnote; palette fix; verify-and-close the two already-fixed issues. *Pure trust + correctness, mostly frontend.*
2. **Verdict engine** in Go (`classify`, `device_kind`, `last_tls/last_dns`, `logger_ok` on `/api/clients`). Replace every fake-green chip with the inferred badge. *The brain lands.*
3. **`/api/clients` 10s memo** + **progressive ClientDetail split** + ensure category index bucket. *Makes the board pollable and the detail instant — prerequisite for live polling.*
4. **Clients recomposed:** person grouping + 5/10/30m snapshot control + 15s auto-refresh + truthful freshness/health chips (the §5 board).
5. **`/api/snapshot`** + **Срез drawer** (§2) — the signature feature, now that the engine and a fast endpoint exist.
6. **Cutoff anchor (`parseRange`) + per-minute reconstruction ribbon** on ClientDetail (lazy domains). *"After 02:05 MSK."*
7. **Categorization rules v2 + `kind`** (hostname-visible only) — ongoing, lowest urgency; sharpens but doesn't gate the verdict.

Ship 1-2 this week; 3-5 are the product-defining sprint; 6-7 are follow-on polish.
