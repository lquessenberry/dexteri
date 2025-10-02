# Testing Guide - New GUI Components

## Quick Test (5 minutes)

### 1. Frontend is already running
```
✅ Frontend: http://localhost:5174
```

### 2. Run a quick scan

In the UI:
1. Enter `https://example.com` in Site A
2. Leave depth at `0` (homepage only for speed)
3. Click "Start Security Scan"
4. Watch progress in terminal

### 3. Test NEW Tabs (after scan completes)

**Pages Tab** 📄
- Click "Pages" tab
- Should show table of crawled pages
- Verify: URL, status code, title, size
- Look for signal indicators (JSON-LD, OG, trackers)

**Marketing Tab** 📈
- Click "Marketing" tab
- Should show:
  - SEO Score
  - Privacy Score
  - Structured Data section (JSON-LD, Microdata)
  - Social Media section (Open Graph, Twitter)
  - SEO Elements (Canonical, Robots, Hreflang)
  - Trackers section

**Tech Stack Tab** 🔧
- Click "Tech Stack" tab
- Should show:
  - CMS section (e.g., "Unknown" or "WordPress")
  - Server section (e.g., "nginx", "Apache")
  - Frameworks list
  - Languages list
  - Libraries list

**Compare Tab** 📊
- Add Site B: `https://example.org`
- Run scan again
- Click "Compare" tab
- Should show side-by-side comparison:
  - Domain names
  - Vulnerability counts
  - Open ports
  - Pages crawled
  - Security scores
  - Diff indicators (↑↓−)

### 4. Test Existing Tabs (verify still working)

✅ **Dashboard** - Security overview
✅ **Scanner** - Results display
✅ **Network** - Network monitor
✅ **Intelligence** - Threat intel
✅ **Advanced** - Settings

---

## Full Test (15 minutes)

### Test 1: Real Website with Marketing

```bash
# In UI:
Site A: https://stripe.com (has lots of marketing signals)
Depth: 1
Start Scan
```

**Expected:**
- Pages tab: Multiple pages
- Marketing tab: High SEO score, multiple trackers
- Tech Stack: React detected

### Test 2: WordPress Site

```bash
Site A: https://wordpress.org
Depth: 0
Start Scan
```

**Expected:**
- Tech Stack: CMS = "WordPress"
- Marketing: Canonical URLs detected

### Test 3: A/B/C Comparison

```bash
Site A: https://github.com
Site B: https://gitlab.com  
Site C: https://bitbucket.org
Depth: 0
Start All Scans
```

**Expected:**
- Compare tab shows all 3 sites
- Diff indicators show differences
- Security scores calculated

---

## What to Look For

### ✅ Success Indicators

- **Pages tab loads** with real data
- **Marketing tab** shows aggregated metrics
- **Tech Stack** detects technologies
- **Compare tab** shows differences
- **No console errors** (check browser DevTools)
- **Loading states** appear briefly
- **Data updates** when switching sites

### 🚨 Potential Issues

**"Loading..." never completes:**
- Check browser console for 404 errors
- Verify backend is running
- Check network tab for API calls

**Empty data:**
- May be normal if site has no signals
- Check backend logs
- Verify scan completed successfully

**TypeScript errors:**
- Check browser console
- Verify all imports are correct

**API errors:**
- 404: Endpoint not found (check backend routes)
- 500: Server error (check backend logs)
- Network error: Backend not running

---

## Debug Commands

### Check if backend is responding:
```bash
curl http://localhost:8099/api/status
```

### Check if frontend is built:
```bash
cd frontend/domain-watcher-box
npm run build
```

### Restart frontend:
```bash
cd frontend/domain-watcher-box
npm run dev
```

### Check console for errors:
```
Open browser DevTools (F12)
Click Console tab
Look for red errors
```

---

## Expected Behavior

### Before Scan
- All new tabs disabled or show "No results"
- Only Dashboard, Advanced tabs active

### During Scan
- Progress shows in Scanner tab
- Terminal shows logs
- Status updates in real-time

### After Scan
- **All 9 tabs become active**
- Pages tab shows table
- Marketing tab shows metrics
- Tech Stack tab shows detections
- Compare tab ready (if multiple sites)
- Export dropdown works

---

## Success Criteria

✅ All 9 tabs accessible after scan  
✅ Pages table displays crawled URLs  
✅ Marketing metrics show aggregated data  
✅ Tech Stack detects at least CMS or server  
✅ Comparison shows differences for A/B/C  
✅ No console errors  
✅ Export works for all formats  
✅ Switching between sites (A/B/C) works  

---

## Report Issues

If you find any issues:

1. **Screenshot the error**
2. **Copy console logs** (F12 → Console)
3. **Note which tab/action caused it**
4. **Copy the exact URL scanned**

I'll fix it immediately! 🔥

---

*Testing Guide - Phase C*  
*Generated: October 1, 2025 @ 21:10 CDT*
