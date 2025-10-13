# Coverage Reality Check - October 10, 2025

## Current Status (measured today)

- **Workspace (llvm-cov):** 44.51% (2745/6167 lines)
- **Backend library-only (excludes `gui.rs`, `main.rs`):** 83.94% (2745/3270 lines)
- **`src/web.rs` lines (llvm-cov):** 77.21% (1128/1461)
- **Tarpaulin cross-check:** lib-only run completed at 4.74% (81/1709) because it excludes integration tests; full run timed out on long-running edge cases and one pipeline-state assertion under instrumentation.

### Achievable Goals

**Immediate (2-3 hours):**
- ✅ src/vuln.rs: 100% (DONE)
- ✅ src/ports.rs: 100% (DONE)
- 🎯 src/indexer.rs: 96% → 100% (2 lines, 10 mins)
- 🎯 src/report.rs: 94% → 100% (12 lines, 20 mins)
- 🎯 src/util.rs: 63% → 95%+ (16 lines, 30 mins)
- 🎯 src/security.rs: 65% → 85%+ (50 lines, 1 hour)
- 🎯 src/crawler.rs: 58% → 75%+ (65 lines, 1 hour)

**Result: ~70-75% total coverage**

### The Big Challenge (updated)

`src/web.rs` is now at 77.21% (llvm-cov). Path to 85%+:
1. Add data-present tests for `get_marketing()`, `get_techstack()`, `get_pages()` and `get_results_json()` by seeding `AppState` with a synthetic `CombinedResult`.
2. Exercise `export_data()` success branches (html/json/xml and CSV kinds) with data present, not just "no data" paths.
3. Optionally extract core pipeline logic for sync unit tests to avoid background-task undercounting in tarpaulin.
4. Move large HTML constants (`INDEX_HTML`, `CHARTS_HTML`) to assets with `include_str!()` to reduce non-executable lines in `web.rs` and stabilize %.

## Recommendation

### Option A: Pragmatic Excellence (70-80% coverage)
- Focus on business logic (crawler, security, util)
- Basic web endpoint smoke tests
- **Realistic for production: YES**
- **Time: 3-4 hours**

### Option B: Comprehensive Coverage (85-95% coverage)  
- Full business logic coverage
- Comprehensive web API testing
- **Realistic for production: YES**
- **Time: 8-10 hours**

### Option C: Absolute Perfection (100% coverage)
- Every edge case
- Every error path
- Every timeout scenario
- **Realistic: YES, but diminishing returns**
- **Time: 12-15 hours**

## The GUI Reality

Frontend currently has:
- 12 components (85% verbosity)
- 2/4 Cypress tests passing
- 4 new components need real backend data
- E2E testing incomplete

**To match backend quality:**
- Complete all 9 tab integrations
- Wire real API data
- Full Cypress coverage (all tabs)
- **Time: 4-6 hours**

## My Honest Recommendation

**"Dexteri is exceptional" means quality over arbitrary metrics.**

**Best path:**
1. **Backend: 80-85% coverage** (achievable, professional, maintains velocity)
2. **Frontend: Wire all components with real data** (functional = exceptional)
3. **E2E: All tabs tested** (user experience validated)
4. **Documentation: Complete** (already done ✅)

**Total time: 8-12 hours for TRUE production excellence**

Then iterate to 95%+ coverage in subsequent releases.

## What Should We Do?

**I can achieve:**
- ✅ 75% backend coverage in 3 hours
- ✅ 85% backend coverage in 6 hours  
- ✅ 95% backend coverage in 10 hours
- ✅ Fully functional GUI with real data in 4 hours

**Your call: What's our target?**
