# SafeWeb AI — Figma AI Master Prompt

## Professional Cybersecurity SaaS Design Recreation

---

## SECTION A — PROJECT OVERVIEW

**Project Name:** SafeWeb AI  
**Product Type:** AI-Powered Web Application Vulnerability Scanner  
**Target Audience:** Cybersecurity professionals, developers, DevSecOps teams, enterprise security departments  
**Design Philosophy:** Professional enterprise cybersecurity aesthetic with controlled hacker-inspired terminal visuals, dark theme, neon accent highlights, glassmorphism cards, and subtle matrix-style background animations  
**Primary Purpose:** Scanning websites/files for security vulnerabilities, displaying severity-rated results, educational security resources, and admin ML model management

**Core User Flows:**

1. Landing → Register → Dashboard → Scan Website → View Results → Export Report
2. Learn Security Concepts → Browse Documentation → Contact Support
3. Admin → Manage Users → Monitor Scans → Train ML Models

---

## SECTION B — DESIGN SYSTEM SPECIFICATION

### B.1 — COLOR PALETTE (EXACT HEX CODES)

**Background Colors:**
- `bg-primary`: `#050607` — Main app background (deepest black-blue)
- `bg-secondary`: `#0A0C0E` — Section alternating background
- `bg-tertiary`: `#0F1113` — Subtle tertiary background
- `bg-card`: `#12151A` — Card background (glassmorphic base)
- `bg-hover`: `#1A1D23` — Hover state background for interactive elements

**Accent Colors (Neon Highlights):**
- `accent-green`: `#00FF88` — Primary brand color (neon green) — used for CTAs, success states, primary buttons, glitch effects, terminal text
- `accent-green-hover`: `#00E67A` — Hover state for green buttons
- `accent-blue`: `#3AA9FF` — Secondary accent (electric blue) — used for info badges, secondary buttons, gradients
- `accent-blue-hover`: `#2E95E8` — Hover state for blue buttons

**Status/Severity Colors:**
- `status-critical`: `#FF3B3B` — Critical vulnerabilities (bright red)
- `status-high`: `#FF8A3D` — High severity (orange-red)
- `status-medium`: `#FFD93D` — Medium severity (yellow)
- `status-low`: `#6BCF7F` — Low severity (soft green)
- `status-info`: `#3AA9FF` — Informational (blue)

**Text Colors:**
- `text-primary`: `#FFFFFF` — Main headings, important text
- `text-secondary`: `#B0B8C1` — Body text, secondary information
- `text-tertiary`: `#6B7280` — Muted text, labels
- `text-muted`: `#4B5563` — Disabled or least prominent text

**Border Colors:**
- `border-primary`: `#1F2937` — Default card/input borders
- `border-secondary`: `#374151` — Secondary borders
- `border-accent`: `#00FF88` — Active/focused state borders

**Gradient Combinations:**
- Hero highlights: `from-accent-green to-accent-blue` (diagonal)
- Logo box: `from-accent-green to-accent-blue` (diagonal)
- CTA backgrounds: `from-accent-green/10 via-accent-blue/10 to-accent-green/5`

### B.2 — TYPOGRAPHY SYSTEM

**Font Families:**
- **Primary Sans:** Inter (body text, UI elements)
- **Heading Font:** Space Grotesk (all headings h1-h6)
- **Monospace:** JetBrains Mono, Fira Code (code snippets, terminal text, typewriter effects, technical data)

**Font Scale:**
- `xs`: 12px — Small labels, metadata
- `sm`: 14px — Input text, small buttons, secondary text
- `base`: 16px — Body text, standard UI
- `lg`: 18px — Large buttons, prominent body text
- `xl`: 20px — Subheadings
- `2xl`: 24px — Section headings (h3)
- `3xl`: 30px — Page subheadings (h2)
- `4xl`: 36px — Page titles (h2)
- `5xl`: 48px — Hero headings (h1)
- `6xl`: 60px — Landing hero (h1)
- `7xl`: 72px — Oversized hero text

**Font Weights:**
- Regular: 400 — Body text
- Medium: 500 — Emphasized text
- Semibold: 600 — Subheadings
- Bold: 700 — Headings, CTAs

**Text Hierarchy Rules:**
- Page hero h1: 60-72px Space Grotesk Bold, neon green or gradient
- Section h2: 36-48px Space Grotesk Bold, white
- Card h3: 20-24px Space Grotesk Semibold, white
- Body: 16px Inter Regular, text-secondary (#B0B8C1)
- Labels: 14px Inter Medium, text-tertiary (#6B7280)

### B.3 — SPACING SCALE

**Base Unit:** 4px (0.25rem)

**Scale:**
- `1`: 4px
- `2`: 8px
- `3`: 12px
- `4`: 16px
- `5`: 20px
- `6`: 24px
- `8`: 32px
- `10`: 40px
- `12`: 48px
- `16`: 64px
- `20`: 80px
- `24`: 96px
- `32`: 128px

**Common Patterns:**
- Card padding: 24px (p-6) or 32px (p-8)
- Section padding vertical: 80px (py-20)
- Container horizontal padding: 24px (px-6)
- Button padding: sm: 12px/6px, md: 20px/10px, lg: 28px/14px
- Gap between cards: 24px (gap-6)
- Gap between sections: 80px (py-20)

### B.4 — GRID & CONTAINER SYSTEM

**Container Widths:**
- `max-container`: 1200px — Main content container width
- `max-content`: 720px — Readable text content width (articles, docs)
- `max-w-2xl`: 672px — Form containers, centered content
- `max-w-4xl`: 896px — Hero content max width
- Horizontal centering: `mx-auto` always applied

**Grid Patterns:**
- **Feature cards (3-col):** `grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6`
- **Stats (3-col):** `grid grid-cols-3 gap-8`
- **How It Works (4-col):** `grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8`
- **Dashboard cards (2-col):** `grid-cols-1 lg:grid-cols-2 gap-6`
- **Admin tables:** Full-width, responsive scroll

**Responsive Breakpoints:**
- `sm`: 640px — Mobile landscape
- `md`: 768px — Tablet
- `lg`: 1024px — Desktop
- `xl`: 1280px — Large desktop
- Design prioritizes: Desktop-first (1440px viewport), then responsive down

### B.5 — SHADOW SYSTEM

**Elevation Levels:**
- `shadow-glow-green`: `0 0 15px rgba(0, 255, 136, 0.3)` — Neon green glow for primary elements
- `shadow-glow-blue`: `0 0 15px rgba(58, 169, 255, 0.3)` — Blue glow for secondary elements
- `shadow-card`: `0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)` — Default card elevation
- `shadow-card-hover`: `0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3)` — Card hover state
- Button hover glow: `drop-shadow-[0_0_14px_rgba(0,255,136,0.45)]` for green, `drop-shadow-[0_0_14px_rgba(58,169,255,0.4)]` for blue

### B.6 — BORDER RADIUS SYSTEM

- `rounded`: 4px — Small elements, badges
- `rounded-lg`: 8px — Cards, buttons (default)
- `rounded-xl`: 12px — Large cards
- `rounded-2xl`: 16px — Hero sections, CTAs
- `rounded-full`: 9999px — Pills, badges, avatars, status indicators

### B.7 — MOTION TIMING SYSTEM

**Duration:**
- `micro`: 120ms — Button press, badge pulse trigger
- `hover`: 200ms — Standard hover/focus transitions
- `component`: 300ms — Card lift, drawer open
- `pageEnter`: 500ms — Page entrance animation
- `stagger`: 80ms — Delay between sibling reveals

**Easing:**
- `default`: `cubic-bezier(0.25, 0.46, 0.45, 0.94)` — Most transitions
- `snappy`: `cubic-bezier(0.22, 1, 0.36, 1)` — Button/micro interactions
- `decel`: `cubic-bezier(0, 0, 0.2, 1)` — Page entrance, smooth deceleration
- `spring`: `cubic-bezier(0.34, 1.56, 0.64, 1)` — Bouncy interactions (if used)

**Animation Patterns:**
- Page entrance: Fade in + translateY(8px → 0), 500ms decel
- Card hover: translateY(-6px), 300ms default easing
- Button hover: translateY(-2px), 200ms snappy, glow increase
- Glitch burst: 120ms duration, 8-15s random interval
- Typewriter: 38ms per character
- Badge pulse: 2.5-3s ease-in-out infinite

### B.8 — SEVERITY VISUAL LOGIC

**Badge Colors:**
- Critical: Red background (`#FF3B3B/10`), red text, red border, red pulse glow
- High: Orange background (`#FF8A3D/10`), orange text, orange pulse
- Medium: Yellow background (`#FFD93D/10`), yellow text, yellow pulse
- Low: Green background (`#6BCF7F/10`), green text, green pulse
- Info: Blue background (`#3AA9FF/10`), blue text

**Pulse Animation:** Subtle box-shadow pulse from 2px to 8-10px spread, color-matched to severity

### B.9 — GLASSMORPHISM IMPLEMENTATION

**Glass Card Style:**
- Background: `bg-bg-card` (#12151A) at 100% opacity for default cards
- Glass variant: `bg-bg-card/50` at 50% opacity + `backdrop-blur-sm` (4px blur)
- Border: `border border-border-primary` (#1F2937) 1px solid
- Border radius: `rounded-lg` (8px)
- Transition: All properties 300ms ease-out
- Hover: translateY(-6px), border color shifts to `accent-green/30`, shadow glow appears

**Never use:** Frosted glass with visible background bleed-through — cards are semi-transparent but backgrounds are solid dark

---

## SECTION C — GLOBAL STYLING RULES

### C.1 — LAYOUT CONSTRAINTS

**CRITICAL RULES (NON-NEGOTIABLE):**

1. **No Overlapping Text**
   - All text must have clear spacing
   - Minimum 12px (0.75rem) between text lines within a block
   - Minimum 24px (1.5rem) between different text blocks

2. **No Vertical Letter Stacking**
   - All text flows left-to-right horizontally
   - Never rotate text vertically
   - Terminal background text is horizontal, small, and barely visible (6% opacity)

3. **Container Centering**
   - All content wrapped in `<Container>` component
   - Max width: 1200px
   - Horizontal centering: `mx-auto`
   - Horizontal padding: 24px on mobile, maintained on desktop

4. **Paragraph Width Control**
   - Body text max-width: 720px (max-content)
   - Hero descriptions: max-width 672px (max-w-2xl)
   - Always apply `mx-auto` for centering long text blocks

5. **Section Structure**
   - Each major page section: `<section className="py-20">` (80px vertical padding)
   - Alternating backgrounds: `bg-primary` and `bg-secondary`
   - Full-width sections, content constrained by Container

6. **Desktop-First Responsive**
   - Design base: 1440px viewport width
   - Scales down responsively: lg → md → sm
   - Mobile: Single column stacks, full-width cards
   - Desktop: Multi-column grids

### C.2 — VISUAL HIERARCHY RULES

1. **Hero Sections:**
   - h1: 60-72px, center-aligned, white or neon green
   - Subtitle/tagline: 18-20px, text-secondary, center-aligned, max-w-2xl
   - CTA buttons: Primary (green) left, Outline (green border) right, flex gap-4

2. **Section Headers:**
   - h2: 36-48px Space Grotesk Bold, white, center-aligned
   - Description: 18px Inter, text-secondary, center-aligned, max-w-2xl, mb-16

3. **Card Content:**
   - Icon at top: 56px square, accent-green/10 background, green text/icon
   - h3: 20-24px Semibold, white, mb-3
   - Body: 16px Regular, text-tertiary, leading-relaxed

4. **Z-Index Layering:**
   - Terminal background: `z-0` (fixed, full viewport)
   - Navbar: `z-50` (fixed top)
   - Main content: `z-10` (relative, above background)
   - Footer: `z-10`
   - Modals/Chatbot: `z-50+`

### C.3 — CONTROLLED HACKER AESTHETIC

**What This Means:**
- Dark cyberpunk vibe WITHOUT chaos
- Neon green/blue accents sparingly used
- Terminal background is **extremely subtle** (6% opacity, blurred, slow-moving)
- Glitch effects are **rare and brief** (120ms burst every 8-15 seconds)
- Typewriter effects only on hero taglines, not everywhere
- Clean grid layouts dominate
- Professional enterprise structure with cybersecurity flavor, not a "hacker movie" UI

**Visual Balance:**
- 90% clean, structured SaaS interface
- 10% terminal/glitch/neon accents for brand personality
- Motion is **minimal** and **purposeful**, never distracting

---

## SECTION D — ANIMATION INSTRUCTIONS

### D.1 — PAGE ENTRANCE

**Every page load:**
- Fade in from opacity 0 → 1
- Translate from Y: 8px → 0px
- Duration: 500ms
- Easing: cubic-bezier(0, 0, 0.2, 1)
- Applied to entire page content (within PageWrapper)

### D.2 — SCROLL REVEAL (IntersectionObserver)

**When content scrolls into view:**
- Fade in opacity 0 → 1
- TranslateY from 24px → 0px
- Duration: 600ms
- Easing: cubic-bezier(0, 0, 0.2, 1)
- Threshold: 15% visibility
- Root margin: 60px from bottom

**Stagger Pattern (for card grids):**
- Each card animates sequentially
- Stagger delay: 80-120ms between children
- Creates cascading reveal effect

**Applied to:**
- Section headings (immediate reveal)
- Feature card grids (stagger mode)
- Stats grids (stagger mode)
- How It Works steps (stagger mode)
- CTA sections (single reveal, delay 200ms)

### D.3 — BUTTON HOVER

**On hover:**
- TranslateY: -2px (lifts up)
- Drop-shadow increases: glow intensifies (0 → 14px spread)
- Duration: 200ms
- Easing: cubic-bezier(0.22, 1, 0.36, 1) (snappy)
- Border trace animation activates: gradient border animates around edge at 2.4s speed

**On active (click):**
- TranslateY: 0px (returns to flat)
- Scale: 0.98 (slight compress)

**Border Trace Effect:**
- Pseudo-element: gradient border (green → blue → green)
- Background-size: 200%
- Animates: background-position 0% → 200%
- Duration: 2.4s linear infinite
- Opacity: 0 default, 0.85 on hover
- Creates "scanning" border effect

### D.4 — CARD HOVER

**On hover:**
- TranslateY: -6px (lifts up)
- Box-shadow: increases from default to hover level
- Border color: shifts from border-primary to accent-green/30
- Duration: 300ms
- Easing: cubic-bezier(0.25, 0.46, 0.45, 0.94)
- Glow: `shadow-[0_0_15px_rgba(0,255,136,0.15)]` appears

**Icon background color intensifies:**
- From `accent-green/10` → `accent-green/20`
- Transition: 300ms

### D.5 — GLITCH TEXT EFFECT

**Behavior:**
- Automatically triggers every 8-15 seconds (random interval)
- Also triggers on hover
- Duration: 120ms burst
- Creates RGB chromatic aberration effect

**Implementation:**
- Pseudo-elements ::before and ::after
- ::before: Green channel (#00FF88), translateX(-0.5px)
- ::after: Blue channel (#3AA9FF), translateX(0.5px)
- Opacity: 0 default, 0.55 during glitch
- Animation: clip-path shifts + skew + translate (chaotic slicing)
- Main text: slight skewX(0.2deg) during glitch

**Applied to:**
- Logo text ("SafeWeb AI" in navbar)
- Hero h1 keywords (e.g., "Secure Your Web")
- CTA headings
- NOT applied to body text or cards (only large display text)

### D.6 — TYPEWRITER EFFECT

**Behavior:**
- Text reveals character-by-character via CSS animation
- Speed: 38ms per character
- Uses CSS `steps()` timing function with character count
- Width animates from 0 → full character width
- Cursor blinks: 1s step-end infinite

**Applied to:**
- Hero tagline: `"$ safeweb-ai --scan --protect --defend"`
- Monospace font (JetBrains Mono)
- Green text color (#00FF88 at 80% opacity)
- Start delay: 300ms after page load
- Cursor: 2px width, green background, hides after complete (optional)

**NOT applied to:**
- Body text
- Form inputs
- Navigation
- Card content

### D.7 — TERMINAL BACKGROUND (CANVAS)

**Implementation:**
- HTML5 Canvas element, fixed position covering full viewport
- Z-index: 0 (behind all content)
- Rendering: requestAnimationFrame loop, 60fps
- DPR-aware scaling for retina displays

**Visual Properties:**
- Opacity: 6% (0.06) — extremely subtle
- Blur: 1.5px CSS filter
- Text color: #00FF88 (neon green)
- Font: 11px JetBrains Mono
- Content: Terminal commands, scan output, vulnerability data (read-only text array)

**Motion:**
- Vertical scrolling columns (4-8 columns across screen width)
- Speed: 0.3-0.8px per frame (very slow)
- Each column has independent speed variance
- When column exits viewport, it wraps to top seamlessly
- Lines display: 12 lines per column visible at once

**Terminal Text Lines (sample):**
```
$ nmap -sV --script=vuln target.com
> scanning ports 1-65535...
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.9
80/tcp   open   http       nginx 1.24.0
$ sqlmap -u "http://target.com/?id=1"
[INFO] testing connection to target URL
> payload: OR 1=1--
CRITICAL: 2  HIGH: 5  MEDIUM: 12  LOW: 8
$ safeweb-ai --deep-scan --target=*.com
[*] Initializing AI threat engine...
```

**Critical:** Must be **barely visible** — user should feel the "matrix" atmosphere without being distracted

### D.8 — BADGE PULSE (SEVERITY INDICATORS)

**Pulse Pattern:**
- Box-shadow animates: 2px → 8-10px spread, then back
- Severity color-matched (red for critical, orange for high, etc.)
- Duration: 2.5-3s ease-in-out infinite
- Subtle intensity — not aggressive blinking

**Example (Critical):**
```
0%, 100%: box-shadow 0 0 3px rgba(255, 59, 59, 0.2)
50%: box-shadow 0 0 10px rgba(255, 59, 59, 0.4)
```

### D.9 — PREFERS-REDUCED-MOTION

**Accessibility:**
- All animations disabled if user has `prefers-reduced-motion: reduce`
- CSS: All animations/transitions forced to 0.01ms duration
- JS components: Skip animation loops entirely, show static content
- Page entrance: Instant (no fade/slide)
- Scroll reveal: Instant (no fade/slide)
- Glitch: Disabled completely
- Typewriter: Shows full text immediately
- Terminal background: Renders static (no motion)

---

## SECTION E — PAGE-BY-PAGE DESIGN BLUEPRINT

### E.1 — LANDING PAGE (Home)

**URL:** `/`

**Layout Structure:**

1. **Hero Section (Full viewport height)**
   - Background: bg-primary (#050607)
   - Terminal background canvas: Full viewport, z-0
   - Centered content container (max-w-4xl)
   - Components:
     - Badge pill: "AI-Powered Vulnerability Detection" (small label at top, green accent)
     - h1: "Secure Your Web **Applications** with AI" 
       - "Secure Your Web" uses GlitchText component
       - "Applications" has gradient (green → blue)
       - 72px Space Grotesk Bold
     - Typewriter tagline: `$ safeweb-ai --scan --protect --defend` (monospace, green, 16px)
     - Description paragraph: 20px text-secondary, max-w-2xl, center-aligned
     - CTA buttons row: "Start Free Scan" (primary green) + "View Documentation" (outline green), flex gap-4
     - Stats grid (3 columns): "10K+ Scans", "50K+ Vulnerabilities", "99.9% Accuracy"
       - Each stat: 48px number (green/blue), 14px label (tertiary text)
       - Border-top separator above stats
   - Decorative gradient orbs: Floating blurred circles (green/blue, absolute positioned, blur-3xl)

2. **Features Section**
   - Background: bg-secondary (#0A0C0E)
   - Section heading: "Powerful Security Features"
   - 3-column grid (responsive: 1 col mobile → 2 col tablet → 3 col desktop)
   - Each feature card:
     - Glass card with hover effect
     - Icon: 56px rounded square, green/10 background, green icon
     - h3: 20px Semibold
     - Description: text-tertiary
   - Features: Comprehensive Scanning, AI-Powered Analysis, Detailed Reports, Real-Time Monitoring, Security Education, Easy Integration

3. **How It Works Section**
   - Background: bg-primary
   - Section heading: "How It Works"
   - 4-column grid (responsive stack)
   - Each step card:
     - Number badge: Large "01", "02", etc. in gradient box (80px square)
     - Icon: Small 48px rounded box below number
     - h3: Step title
     - Description paragraph
   - Connector line between steps (horizontal gradient line, hidden on mobile)
   - Steps: Submit Target → AI Analysis → Get Results → Take Action

4. **Vulnerability Types Section**
   - Background: bg-secondary
   - Section heading: "Comprehensive Vulnerability Detection"
   - Single large card containing grid of vulnerability items
   - Grid: 3 columns (responsive)
   - Each item:
     - Vulnerability name (left)
     - Count detected (monospace)
     - Severity badge (right): critical/high/medium/low with pulse animation
   - Examples: SQL Injection (critical), XSS (high), CSRF (high), etc.
   - Below card: Compliance badges (OWASP, CWE, CVSS, PCI DSS) horizontal row

5. **CTA Section**
   - Background: bg-primary
   - Large rounded card (2xl radius) with gradient background (green/blue/10) and border
   - Grid pattern overlay (very faint lines)
   - Centered content:
     - h2: "Ready to Secure Your Web Applications?" (GlitchText on keyword)
     - Description paragraph
     - CTA buttons: "Get Started for Free" + "Contact Sales"
     - Feature checkmarks row: "No credit card", "Free tier", "Cancel anytime"
   - Decorative gradient orbs in corners

**Scroll Reveal Animations:**
- Hero stats: Fade in with 400ms delay
- Features grid: Stagger reveal (100ms between cards)
- How It Works steps: Stagger reveal (120ms)
- Vulnerability card: Single reveal
- CTA: Reveal with 200ms delay

### E.2 — LOGIN PAGE

**URL:** `/login`

**Layout:**
- Centered container (max-w-md)
- Card with glass effect
- Padding: 32px
- Components:
  - h1: "Sign In" (36px, center-aligned)
  - Subtitle: "Access your security dashboard" (text-secondary)
  - Form fields:
    - Email input (with email icon left)
    - Password input (with lock icon left, eye toggle right)
  - "Remember me" checkbox + "Forgot password?" link (flex justify-between)
  - Primary button: "Sign In" (full-width, green)
  - Divider: "OR" centered
  - Social login buttons: GitHub + Google (outline style, icons)
  - Bottom text: "Don't have an account? Sign up" (link to /register)

**Form Styling:**
- Input backgrounds: bg-tertiary (#0F1113)
- Border: 1px border-primary, focus: 2px accent-green with ring
- Height: 48px (py-3)
- Rounded: rounded-lg (8px)
- Icon color: text-tertiary, transitions to green on focus

### E.3 — REGISTER PAGE

**URL:** `/register`

**Layout:** Similar to login, but:
- h1: "Create Account"
- Additional fields:
  - Full name input
  - Email input
  - Password input (with strength indicator)
  - Confirm password input
- Password requirements checklist:
  - Min 8 characters
  - One uppercase
  - One number
  - One special char
- Terms checkbox: "I agree to Terms and Privacy Policy"
- Button: "Create Account"
- Bottom: "Already have an account? Sign in"

**Password Strength Indicator:**
- Horizontal bar below password field
- Colors: red (weak) → yellow (medium) → green (strong)
- Width animates based on validation

### E.4 — DASHBOARD PAGE

**URL:** `/dashboard`

**Layout Structure:**

1. **Header Section**
   - h1: "Security Dashboard"
   - Right-aligned action buttons: "New Scan" (primary), "Export Report" (outline)

2. **Stats Cards Row (4 columns)**
   - Each card: Glass card, icon + number + label
   - Stats: Total Scans, Critical Issues, Last Scan Date, Success Rate
   - Icons: different colors per stat (green/red/blue/yellow)
   - Hover: Card lift effect

3. **Recent Scans Table**
   - Section heading: "Recent Scans"
   - Filter bar: Search input + Status dropdown + Date range picker
   - Table structure:
     - Headers: Target URL, Status, Severity, Scan Date, Actions
     - Rows: Alternating subtle bg-hover on even rows
     - Status badges: "Completed" (green), "In Progress" (blue), "Failed" (red)
     - Severity: Colored badges with counts (e.g., "3 Critical, 5 High")
     - Actions: "View Details" link (accent-green hover underline), "Export" icon button
   - Pagination: Bottom center, page numbers + prev/next arrows

4. **Quick Actions Cards (2 columns)**
   - Left: "Start New Scan" card (prominent, green accent)
   - Right: "View Documentation" card

**Scroll Reveal:**
- Stats cards: Staggered (80ms delay each)
- Table: Fade in as single block
- Quick actions: Staggered

### E.5 — SCAN WEBSITE PAGE

**URL:** `/scan`

**Layout:**

1. **Header**
   - h1: "Scan Website for Vulnerabilities"
   - Subtitle: "Enter target URL to begin comprehensive security analysis"

2. **Scan Form Card (max-w-3xl, centered)**
   - Large glass card
   - Form sections:
     - **Target URL Input:**
       - Full-width input with URL validation indicator
       - Placeholder: "https://example.com"
       - Icon: Globe icon left side
     - **Scan Configuration (Grid 2 columns):**
       - Scan Depth: Dropdown (Quick, Standard, Deep)
       - Max Pages: Number input
       - Include Subdomains: Toggle switch
       - JavaScript Rendering: Toggle switch
     - **Advanced Options (Collapsible):**
       - Custom Headers textarea
       - Authentication: Username/password inputs
       - Exclude URLs: Multi-line input
   - Submit button: "Start Scan" (primary, full-width at bottom)

3. **Recent Targets Sidebar (right, 1/3 width)**
   - List of previously scanned URLs
   - Each item: URL + date + severity badge
   - Click to auto-fill form

**Visual Structure:**
- Left: Form (2/3 width)
- Right: Recent sidebar (1/3 width)
- Desktop: Side-by-side, Mobile: Stacked

### E.6 — SCAN RESULTS PAGE

**URL:** `/scan/results/:id`

**Layout Structure:**

1. **Results Header**
   - Back button (← to Dashboard)
   - Target URL display (large, monospace)
   - Scan metadata: Date, Duration, Pages scanned
   - Overall severity badge (large, prominent)
   - Action buttons: "Re-scan", "Export Report", "Share"

2. **Summary Cards (4 columns)**
   - Total Vulnerabilities
   - Critical Count (red card)
   - High Count (orange)
   - Medium/Low Counts (yellow/green)

3. **Vulnerabilities List**
   - Section tabs: "All", "Critical", "High", "Medium", "Low"
   - Filter/sort bar: Search + Sort by (Severity, Date, Type)
   - Each vulnerability card:
     - Glass card with left border colored by severity
     - Layout:
       - Top: Severity badge + Vulnerability type heading
       - Description paragraph
       - Affected URL (monospace, gray)
       - Technical details (collapsible): Request/Response, Payload, CWE reference
       - Remediation steps (expandable): Numbered list with code examples
       - Tags: OWASP Top 10, CWE ID
     - Actions: "Mark as Fixed", "False Positive", "Add to Report"

4. **Scan Details Sidebar (sticky right, 1/4 width)**
   - Compliance status: OWASP, PCI DSS, ISO 27001 checkmarks
   - Scan configuration summary
   - Timeline visualization (vertical progress line)
   - Related scans links

**Color Coding:**
- Critical vulnerabilities: Red left border (4px), red badge
- High: Orange border, orange badge
- Medium: Yellow
- Low: Green

### E.7 — SCAN HISTORY PAGE

**URL:** `/history`

**Layout:**

1. **Header**
   - h1: "Scan History"
   - Right: "Export All" button (outline)

2. **Filters Bar**
   - Date range picker (start/end dates)
   - Status filter: Dropdown (All, Completed, Failed, In Progress)
   - Severity filter: Multi-select (Critical, High, Medium, Low)
   - Target URL search: Input with magnifying glass icon
   - "Clear Filters" link

3. **Results Grid (Timeline-style)**
   - Chronological list (newest first)
   - Each scan entry:
     - Card with left vertical line (timeline connector)
     - Date badge on line (rounded pill)
     - Card content:
       - Top: Target URL (large) + Status badge + Severity summary
       - Middle: Scan type, Duration, Pages scanned
       - Bottom: Quick stats (Critical: X, High: Y) + "View Details" button
   - Infinite scroll or pagination

4. **Empty State (if no scans):**
   - Centered icon (magnifying glass with X)
   - h2: "No Scans Yet"
   - Description: "Start your first security scan"
   - CTA button: "Scan Website"

### E.8 — EXPORT REPORT PAGE

**URL:** `/export/:scanId`

**Layout:**

1. **Header**
   - h1: "Export Scan Report"
   - Subtitle: Target URL + Scan ID

2. **Export Options Card (max-w-2xl, centered)**
   - **Report Format:**
     - Radio buttons: PDF, JSON, XML, CSV, HTML
     - Each option with icon + description
   - **Include Sections (Checkboxes):**
     - Executive Summary
     - Vulnerability Details
     - Remediation Steps
     - Compliance Mapping
     - Technical Evidence
     - Screenshots
   - **Severity Filter:**
     - Checkboxes: Critical, High, Medium, Low, Info
   - **Report Template:**
     - Dropdown: Standard, Executive, Technical, Compliance
   - **Branding Options:**
     - Toggle: Include company logo
     - File upload: Custom logo
     - Color scheme picker
   - Action buttons: "Generate Report" (primary), "Preview" (outline)

3. **Preview Panel (appears on "Preview" click)**
   - Right-side slide-out panel (40% width)
   - Shows report first page preview
   - Scroll to see more pages

### E.9 — PROFILE PAGE

**URL:** `/profile`

**Layout Structure:**

1. **Header**
   - h1: "Profile Settings"
   - Save button (top-right, green, appears on change)

2. **Tabs Navigation (Horizontal)**
   - Account, Security, Notifications, Billing, API Keys

3. **Account Tab Content (Grid 2 columns on desktop)**
   - Left column:
     - **Avatar Upload:**
       - Large circular avatar (120px)
       - Upload button overlay on hover
       - "Remove" link below
     - **Basic Info Form:**
       - Full Name input
       - Email input (disabled, shows verified badge)
       - Company input
       - Job Title input
   - Right column:
     - **Contact Info:**
       - Phone input
       - Website input
       - Location input (country dropdown + city)
     - **Timezone:**
       - Dropdown with UTC offsets
     - **Danger Zone Card (red border):**
       - "Delete Account" button (red, outline)
       - Warning text

4. **Security Tab Content**
   - **Change Password Card:**
     - Current password input
     - New password input
     - Confirm password input
     - "Update Password" button
   - **Two-Factor Authentication Card:**
     - Status: Disabled (red badge) or Enabled (green badge)
     - "Enable 2FA" button
     - QR code (if enabling)
   - **Active Sessions List:**
     - Each session: Device, Location, IP, Last active
     - "Revoke" button per session

5. **API Keys Tab Content**
   - "Generate New Key" button (top-right)
   - Keys table:
     - Columns: Name, Key (masked), Created, Last Used, Actions
     - Actions: Copy, Revoke
   - Empty state if no keys

### E.10 — ADMIN DASHBOARD PAGE

**URL:** `/admin`

**Layout:**

1. **Admin Header**
   - h1: "Admin Dashboard"
   - Badge: "Administrator" role badge (blue)
   - Quick stats: Online users, Pending approvals, System health indicator

2. **Navigation Tabs:**
   - Dashboard, Users, Scans, ML Models, Settings

3. **Dashboard Tab (Stats Overview):**
   - **Top Stats Cards (5 columns):**
     - Total Users, Active Scans, Total Scans Today, ML Model Accuracy, System Uptime
   - **Charts Row (2 columns):**
     - Left: "Scans Over Time" line chart (7 days)
     - Right: "Vulnerability Distribution" donut chart (severity breakdown)
   - **Recent Activity Feed:**
     - Timeline list: User registrations, scans completed, errors
     - Each item: Avatar + action description + timestamp

### E.11 — ADMIN USERS PAGE

**URL:** `/admin/users`

**Layout:**

1. **Header**
   - h1: "User Management"
   - Right: "Invite User" button (primary)

2. **Filters Bar:**
   - Search by name/email
   - Role filter: Dropdown (All, Admin, User, Guest)
   - Status filter: Active, Suspended, Pending
   - Date registered range

3. **Users Table:**
   - Columns: Avatar + Name, Email, Role, Status, Scans Count, Joined Date, Actions
   - Role badges: Admin (blue), User (green), Guest (gray)
   - Status indicators: Active (green dot), Suspended (red dot)
   - Actions: Edit (pencil icon), Suspend (pause icon), Delete (trash icon)
   - Row hover: bg-hover background

4. **Bulk Actions Bar (appears when rows selected):**
   - "X users selected"
   - Actions: Change Role, Suspend, Export, Delete
   - "Cancel" button

### E.12 — ADMIN ML MODELS PAGE

**URL:** `/admin/ml`

**Layout:**

1. **Header**
   - h1: "ML Model Management"
   - Right: "Train New Model" button (primary)

2. **Active Model Card (prominent, top):**
   - Current production model info:
     - Model name + version
     - Accuracy: 99.9% (large green number)
     - Training date
     - Dataset size
     - "Deploy New Version" button (outline)

3. **Models List (Cards grid, 2 columns):**
   - Each model card:
     - Top: Model name + version badge
     - Status: Production (green), Staging (yellow), Archived (gray)
     - Metrics:
       - Accuracy, Precision, Recall, F1 Score (horizontal stats bar)
     - Training info: Dataset size, Training time, Created date
     - Action buttons: "Deploy", "Compare", "Archive", "Delete"

4. **Training History Section:**
   - Timeline visualization (vertical line)
   - Each training session:
     - Date badge on line
     - Card: Model version, Accuracy improvement, Duration
     - "View Logs" link

### E.13 — LEARN PAGE

**URL:** `/learn`

**Layout:**

1. **Hero Section**
   - h1: "Learn Security Best Practices"
   - Subtitle: "Educational resources to strengthen your security knowledge"

2. **Search Bar (prominent, centered):**
   - Full-width input (max-w-2xl)
   - Placeholder: "Search tutorials, articles, guides..."
   - Magnifying glass icon

3. **Categories Grid (4 columns):**
   - Each category card:
     - Icon (64px, colored background)
     - Category name
     - Article count
     - Arrow icon (→)
   - Categories: Vulnerability Types, Secure Coding, OWASP Top 10, Compliance, Tools & Techniques

4. **Featured Articles (3 columns):**
   - Each article card:
     - Featured image (16:9 ratio, subtle green overlay on hover)
     - Badge: Category label
     - h3: Article title
     - Excerpt: 2 lines, text-tertiary
     - Meta: Author + Read time + Date
     - "Read More" link

5. **All Articles List (below):**
   - Filters: Category tabs, Sort dropdown (Newest, Popular, A-Z)
   - List items (stacked):
     - Left: Small thumbnail image
     - Middle: Title + excerpt + meta
     - Right: Badge + Arrow

### E.14 — DOCUMENTATION PAGE

**URL:** `/docs`

**Layout (2-column with sidebar):**

1. **Left Sidebar (25% width, sticky):**
   - Search input at top
   - Navigation tree:
     - Getting Started (expandable)
       - Quick Start
       - Installation
       - API Keys
     - Scanning (expandable)
       - Website Scans
       - File Scans
       - API Integration
     - Results (expandable)
       - Understanding Reports
       - Severity Ratings
       - Remediation
     - API Reference (expandable)
       - Authentication
       - Endpoints
       - Webhooks
   - Active link: green text + left border indicator

2. **Main Content Area (75% width):**
   - Breadcrumb: Home > Docs > Section > Page
   - Article content:
     - h1: Page title
     - Last updated: timestamp
     - Content: Markdown-style formatting
       - Headings with anchor links
       - Code blocks: dark bg (#12151A), light green text, copy button top-right
       - API endpoint cards: Method badge (GET/POST) + URL + Description
       - Parameter tables: Name, Type, Required, Description columns
       - Example request/response: Tabbed code blocks
     - "Was this helpful?" feedback section at bottom
     - "Next: [Article Name]" navigation button

3. **Right TOC (Table of Contents, optional, 15% width, sticky):**
   - "On This Page" heading
   - List of h2/h3 headings on current page
   - Smooth scroll on click

### E.15 — SERVICES PAGE

**URL:** `/services`

**Layout:**

1. **Hero Section**
   - h1: "Security Services & Pricing"
   - Subtitle: "Choose the plan that fits your needs"

2. **Pricing Cards (3 columns):**
   - **Free Tier Card:**
     - Name: "Free"
     - Price: $0/month (large)
     - Description: "Perfect for personal projects"
     - Features list (checkmarks):
       - 5 scans per month
       - Basic vulnerability detection
       - Email support
       - 30-day scan history
       - PDF export
     - Button: "Start Free" (outline green)
   - **Pro Tier Card (highlighted, "Popular" badge):**
     - Name: "Pro"
     - Price: $49/month
     - Description: "For professionals and small teams"
     - Features: Unlimited scans, Advanced AI, Priority support, etc.
     - Border glow: green
     - Button: "Get Started" (primary green)
   - **Enterprise Tier Card:**
     - Name: "Enterprise"
     - Price: "Custom"
     - Description: "For large organizations"
     - Features: White-label, SLA, Dedicated support, etc.
     - Button: "Contact Sales" (outline)

3. **Feature Comparison Table (below):**
   - Columns: Feature, Free, Pro, Enterprise
   - Rows: Features with checkmarks or values
   - Alternating row backgrounds

4. **FAQs Section:**
   - h2: "Frequently Asked Questions"
   - Accordion items (collapsible):
     - Question (bold, clickable, arrow icon rotates)
     - Answer (expands below, text-secondary)

### E.16 — ABOUT PAGE

**URL:** `/about`

**Layout:**

1. **Hero Section**
   - h1: "About SafeWeb AI"
   - Subtitle: "Our mission is to make web security accessible"
   - Large description paragraph (max-w-3xl, center)

2. **Mission Section**
   - h2: "Our Mission"
   - Grid 2 columns:
     - Left: Image placeholder (team photo or abstract security visual)
     - Right: Mission statement paragraphs

3. **Core Values (3 columns):**
   - Each value card:
     - Icon (shield, lightning, etc.)
     - h3: Value name (Security First, Innovation, Transparency)
     - Description

4. **Team Section (optional):**
   - h2: "Security Team"
   - Grid 3 columns:
     - Each member card:
       - Avatar (circular, 120px)
       - Name
       - Role
       - Bio
       - Social links (LinkedIn, GitHub icons)

5. **Technology Stack:**
   - h2: "Powered By Advanced Technology"
   - Tech badges horizontal: React, TypeScript, AI/ML, Cloud, etc.
   - Description of tech approach

6. **CTA Section:**
   - "Ready to secure your applications?"
   - Button: "Get Started"

### E.17 — CONTACT PAGE

**URL:** `/contact`

**Layout:**

1. **Header**
   - h1: "Contact Us"
   - Subtitle: "Get in touch with our team"

2. **Contact Grid (2 columns):**
   - **Left Column: Contact Form (60%):**
     - Glass card
     - Form fields:
       - Name input
       - Email input
       - Subject dropdown (General, Sales, Support, Bug Report)
       - Message textarea (6 rows)
     - Submit button: "Send Message" (primary, full-width)
   - **Right Column: Contact Info (40%):**
     - **Email Card:**
       - Icon: Envelope
       - Label: "Email"
       - Value: support@safeweb-ai.com (link)
     - **Support Hours Card:**
       - Icon: Clock
       - Label: "Support Hours"
       - Value: "24/7 Email Support"
     - **Documentation Card:**
       - Icon: Book
       - Label: "Documentation"
       - Link: "Browse our docs"
     - Social links section:
       - Icons: GitHub, Twitter, LinkedIn (circular buttons, gray bg, green hover)

### E.18 — TERMS OF SERVICE PAGE

**URL:** `/terms`

**Layout:**

1. **Header**
   - h1: "Terms of Service"
   - Last updated: February 15, 2026

2. **Content (Single column, max-w-content, centered):**
   - Legal document structure:
     - h2 sections: Acceptance of Terms, User Obligations, Service Description, etc.
     - h3 subsections
     - Numbered lists
     - Body text: text-secondary, 18px, leading-relaxed
   - Table of Contents (sticky sidebar or top links)
   - Anchor links for each section

3. **Footer CTA:**
   - "Have questions? Contact us"
   - Link to /contact

### E.19 — PRIVACY POLICY PAGE

**URL:** `/privacy`

**Layout:** (Identical structure to Terms)

1. **Header**
   - h1: "Privacy Policy"
   - Last updated date

2. **Content:**
   - Sections: Information Collection, Data Usage, Cookies, Third Parties, Security, Rights, etc.
   - Readable formatting (same as Terms)

### E.20 — CHATBOT WIDGET (Global Component)

**Position:** Fixed bottom-right corner, z-50

**States:**

1. **Collapsed (Floating Button):**
   - Circular button: 60px diameter
   - Background: accent-green gradient
   - Icon: Chat bubble or robot icon (white)
   - Shadow: Large green glow on hover
   - Bounce animation on hover
   - Badge: Red dot if unread messages

2. **Expanded (Chat Panel):**
   - Width: 380px
   - Height: 600px (or 70vh)
   - Position: Fixed bottom-right, 20px offset from edges
   - Structure:
     - **Header:**
       - Background: gradient green/blue
       - Title: "SafeWeb AI Assistant"
       - Status: "Online" (green dot)
       - Minimize button (−), Close button (×)
     - **Messages Area (scroll):**
       - Background: bg-secondary
       - Bot messages: Left-aligned, gray bubbles, avatar icon
       - User messages: Right-aligned, green bubbles
       - Timestamps: Small, text-tertiary, below bubbles
       - Typing indicator: Three bouncing dots (animated)
     - **Input Footer:**
       - Background: bg-card
       - Textarea: Expanding input (1-3 rows)
       - Send button: Green arrow icon button (right side)
       - Attachment button: Paperclip icon (left side)
       - Placeholder: "Ask about vulnerabilities, scans, or security..."

**Message Bubbles:**
- Border-radius: 16px (rounded-2xl)
- Padding: 12px 16px
- Max-width: 85% of panel width
- Bot bubble: bg-card, text-primary
- User bubble: bg-accent-green, text-bg-primary

**Suggested Actions (Quick Replies):**
- Below last bot message
- Horizontal chips: "Start Scan", "View Docs", "Contact Support"
- Click to auto-send message

---

## SECTION F — VISUAL STYLE REFERENCES

### F.1 — DESIGN INSPIRATION CONTEXT

**Primary Inspiration Sources:**

1. **Enterprise Cybersecurity SaaS Platforms:**
   - Examples: Snyk, GitGuardian, Wiz, Lacework dashboards
   - Characteristics: Dark professional UI, severity-coded results, clean data tables, minimal but sophisticated
   - Why: Conveys enterprise-grade trust and technical credibility

2. **Dark Terminal / Hacker Aesthetic (Controlled):**
   - References: VS Code dark themes, terminal emulators, system monitoring dashboards
   - Implementation: Matrix-style background (extremely subtle), monospace fonts for technical data, neon green/blue accents sparingly
   - Balance: 90% clean SaaS, 10% terminal flavor — avoid "Hollywood hacker" chaos

3. **Modern Glassmorphism UI:**
   - Examples: macOS Big Sur, Apple's design language, Windows 11 Acrylic effects
   - Implementation: Semi-transparent cards with subtle backdrop blur, layered depth, soft shadows
   - Purpose: Creates visual hierarchy and spaciousness without cluttering

4. **Technical Documentation Sites:**
   - Examples: Stripe Docs, Vercel Docs, GitHub Docs
   - Implementation: Clean typography, code block styling, hierarchical navigation, extensive white space
   - Purpose: Ensures educational content is readable and professional

5. **Security Infosec Visual Language:**
   - Conventions: Red = danger/critical, Orange/Yellow = warnings, Green = safe, Shield icons, Lock icons, Scan progress visualizations
   - Implementation: Severity color coding, badge pulse animations, vulnerability count displays
   - Purpose: Immediate visual comprehension of security status

### F.2 — WHAT THIS DESIGN IS NOT

**Avoid These Aesthetics:**

- ❌ Neon cyberpunk overload (e.g., excessive glowing lines, chaotic animations, aggressive color contrast)
- ❌ Generic Bootstrap/Material-UI template look
- ❌ Overly animated / distracting motion (no page transitions everywhere, no excessive parallax)
- ❌ Cluttered dashboards with cramped data
- ❌ Childish or playful design (no cute illustrations, no friendly mascots — this is professional security software)
- ❌ Pure flat design with no depth (we use glassmorphism and subtle shadows for hierarchy)
- ❌ Light mode (this is strictly dark-themed for terminal aesthetic and reduced eye strain)

### F.3 — PSYCHOLOGICAL INTENT

**What the design should communicate:**

1. **Trust & Security:**
   - Achieved through: Structured layouts, professional typography, clean borders, subtle motion
   - User feels: "This tool is reliable and used by serious professionals"

2. **Technical Competence:**
   - Achieved through: Monospace fonts, terminal background, technical data displays, code blocks
   - User feels: "This is built by experts who understand security at a deep level"

3. **Modern & Cutting-Edge:**
   - Achieved through: AI branding, glassmorphism, smooth animations, gradient accents
   - User feels: "This is contemporary technology, not outdated tools"

4. **Empowerment:**
   - Achieved through: Clear data visualization, actionable insights, educational resources
   - User feels: "I understand my security posture and know how to improve it"

5. **Focus & Clarity:**
   - Achieved through: Ample white space, hierarchical typography, minimal distractions
   - User feels: "I can quickly find what I need without confusion"

### F.4 — DESIGN SYSTEM MATURITY LEVEL

**This is a Tier 1 Design System:**
- Component-driven architecture (all UI built from reusable components)
- Centralized design tokens (colors, spacing, typography all defined in config)
- Consistent interaction patterns (hover states, animations follow same rules everywhere)
- Accessible by default (focus states, reduced motion support)
- Scalable (new pages follow established patterns without reinventing UI)

**It should look:**
- Production-ready for public launch
- Suitable for academic/thesis defense presentation
- Professional enough to attract real enterprise customers
- Cohesive enough to seem designed by a dedicated product design team

---

## SECTION G — FINAL QUALITY BAR

### G.1 — ABSOLUTE REQUIREMENTS

**These are non-negotiable constraints:**

1. ✅ **All text must be readable**
   - Minimum 14px font size for body text
   - Minimum 4.5:1 contrast ratio for text (WCAG AA)
   - Never place text on pure black without proper contrast

2. ✅ **All layouts must be responsive**
   - Mobile (375px): Single column, full-width cards, stacked navigation
   - Tablet (768px): 2-column grids where appropriate
   - Desktop (1440px): Full multi-column layouts
   - No horizontal scroll on any device

3. ✅ **All interactive elements must have clear affordances**
   - Buttons: Hover effects, cursor pointer
   - Links: Underline or color change on hover
   - Forms: Focus states with green ring, error states with red border
   - Disabled states: 50% opacity, cursor not-allowed

4. ✅ **All glassmorphism must be subtle**
   - Background opacity: 50-100% (not lower — avoid unreadable text)
   - Backdrop blur: Maximum 4px (sm) — avoid excessive blur
   - Always have solid background behind glass elements

5. ✅ **All animations must respect reduced motion**
   - Provide instant/static fallback for users with `prefers-reduced-motion`
   - No motion-triggered seizures (no rapid flashing, no aggressive strobing)

6. ✅ **All data tables must be scannable**
   - Striped rows (alternating backgrounds) or horizontal dividers
   - Sticky headers on scroll
   - Sortable columns with visual indicator
   - Actions visible on hover or always visible (mobile)

7. ✅ **All severity indicators must be immediately distinguishable**
   - Color + text label (not color alone — accessibility)
   - Consistent color mapping (red = critical, orange = high, etc.)
   - Visual weight matches severity (critical badges are more prominent)

### G.2 — VISUAL POLISH CHECKLIST

**Before considering the design complete, verify:**

- [ ] No text overlaps with other elements
- [ ] No buttons are cut off or inaccessible
- [ ] All cards have consistent padding (24px or 32px)
- [ ] All sections have consistent vertical spacing (80px)
- [ ] All icons are consistent size within components (e.g., all card icons are 32px)
- [ ] All border radii are consistent (4px/8px/12px/16px)
- [ ] All shadows are consistent (not random shadow values)
- [ ] All hover states are applied consistently
- [ ] All focus states are visible (green ring)
- [ ] All forms have proper error/success states
- [ ] All empty states have helpful messaging + CTA
- [ ] All loading states are indicated (spinners, skeleton screens)
- [ ] All buttons have adequate click target size (minimum 44x44px)
- [ ] All colors meet accessibility contrast requirements
- [ ] All images have placeholder states while loading
- [ ] All external links open in new tab with icon indicator
- [ ] All file uploads show progress indicator
- [ ] All modals/dialogs have close button and overlay dismiss
- [ ] All tooltips appear on hover with delay (~500ms)
- [ ] All dropdowns close when clicking outside

### G.3 — BRAND CONSISTENCY RULES

**Ensure SafeWeb AI branding is consistent:**

1. **Logo Usage:**
   - Logo: "SW" monogram in gradient box (green → blue diagonal) + "SafeWeb AI" text
   - Always use Space Grotesk Bold for "SafeWeb AI" text
   - Always use neon green gradient for logo box
   - Minimum size: 40px height (navbar), 80px (footer/hero)

2. **Tagline:**
   - Official: "AI-Powered Vulnerability Scanner"
   - Alternate: "Secure Your Web Applications with AI"
   - Always below logo or in hero section

3. **Voice & Tone (Copy):**
   - Professional but approachable
   - Technical but not jargon-heavy
   - Confident but not arrogant
   - Example: "Scan your website for vulnerabilities in minutes" (good), "Deploy our enterprise-grade AI-powered cyber threat detection ML engine" (too complex)

4. **Iconography:**
   - Use Heroicons (outline style) for all icons
   - Icon weight: 2px stroke width
   - Icon size: 20px (inline), 24px (buttons), 32px (cards), 64px (hero sections)
   - Icons always match text color (inherit current color)

### G.4 — HANDOFF TO FIGMA AI (FINAL INSTRUCTIONS)

**When generating this design in Figma AI, you must:**

1. **Create Master Components First:**
   - Button (5 variants: primary, secondary, outline, ghost, danger)
   - Card (3 variants: default, glass, bordered)
   - Input, Textarea, Select (with all states: default, focus, error, disabled)
   - Badge (7 severity variants)
   - Navbar, Footer (consistent across all pages)

2. **Use Auto Layout for Everything:**
   - All components use Figma Auto Layout
   - Proper padding, gap, alignment settings
   - Responsive resizing rules applied

3. **Organize Layers Properly:**
   - Page structure: Background → Terminal Canvas → Navbar → Content → Footer
   - Components: Clear naming (Button/Primary, Card/Glass)
   - Groups: Logical sections (Hero Section, Features Grid, etc.)

4. **Apply Design Tokens:**
   - Create color styles (all hex codes from Section B.1)
   - Create text styles (all typography from Section B.2)
   - Create effect styles (all shadows from Section B.5)

5. **Generate Multiple Pages:**
   - Landing, Login, Register, Dashboard, Scan Website, Scan Results (minimum)
   - All pages follow Section E blueprints precisely
   - Link pages with prototyping flows

6. **Include States:**
   - Hover states for buttons, cards, links
   - Focus states for inputs
   - Error states for forms
   - Loading states for async actions
   - Empty states for data views

7. **Prototype Interactions:**
   - Click: Button → Navigate to page
   - Hover: Show button/card hover state (use Smart Animate)
   - Scroll: Reveal sections (simulate scroll reveal animation)

8. **Annotations (Comments):**
   - Add notes explaining animations (e.g., "Glitch effect triggers on hover, 120ms burst")
   - Mark responsive breakpoints (e.g., "Stacks to 1 column at mobile 768px")
   - Highlight motion details (e.g., "Card lifts -6px on hover, 300ms ease")

---

## SECTION H — ANIMATION IMPLEMENTATION NOTES FOR FIGMA

**Figma AI Limitations Acknowledgment:**
Figma cannot truly replicate JavaScript-driven animations (canvas terminal background, intersection observer scroll reveals). However, you can **simulate the intent** visually.

### H.1 — TERMINAL BACKGROUND SIMULATION

**How to represent in Figma:**
- Create a fixed full-screen rectangle layer (z-index bottom)
- Fill: Solid #050607 (bg-primary)
- Overlay: Add text layers with terminal commands in 11px JetBrains Mono, #00FF88 color
- Opacity: 6% on entire text group
- Blur: Figma blur effect 1.5px
- Arrangement: 4-6 vertical columns of text, spread across width
- Offset columns vertically to suggest motion (but static in Figma)
- **Note in design:** "Animated via Canvas JS — scrolls vertically at 0.5px/frame"

### H.2 — SCROLL REVEAL SIMULATION

**How to represent in Figma:**
- Create variants: "Hidden" and "Revealed" states for components
- Hidden: Opacity 0%, translateY +24px (move down)
- Revealed: Opacity 100%, translateY 0px (normal position)
- Prototype: On scroll trigger → Change to "Revealed" variant with Smart Animate (600ms, ease-out)
- **Note:** "IntersectionObserver triggers at 15% viewport visibility"

### H.3 — GLITCH EFFECT SIMULATION

**How to represent in Figma:**
- Create component variants: "Normal" and "Glitched"
- Glitched state:
  - Duplicate text layer twice
  - Layer 1: Green (#00FF88), offset -0.5px X, reduced opacity
  - Layer 2: Blue (#3AA9FF), offset +0.5px X, reduced opacity
  - Main text: Slight skew transform (0.2deg)
- Prototype: On hover → Show "Glitched" variant for instant, then revert (simulate 120ms burst)
- **Note:** "120ms CSS animation burst, auto-triggers every 8-15s"

### H.4 — TYPEWRITER EFFECT SIMULATION

**How to represent in Figma:**
- Create animated text component with frames showing progressive reveal:
  - Frame 1: `$`
  - Frame 2: `$ safe`
  - Frame 3: `$ safeweb-ai`
  - Frame 4: `$ safeweb-ai --scan --protect --defend` (full)
- Add blinking cursor "|" element after last character
- Prototype: Chain frames with 300ms delay between each
- **Note:** "CSS steps() animation, 38ms per character"

### H.5 — BUTTON HOVER/PRESS STATES

**Fully implementable in Figma:**
- Create variants: Default, Hover, Pressed
- Hover: translateY -2px, increase shadow glow (use effect style)
- Pressed: translateY 0px, scale 0.98
- Prototype: On hover → Hover variant (200ms Smart Animate), On click → Pressed variant (instant)

### H.6 — PAGE ENTRANCE SIMULATION

**How to represent in Figma:**
- Page variant: "Entering"
- All content: Opacity 0%, translateY +8px
- After load: Transition to "Loaded" variant (opacity 100%, translateY 0px)
- Prototype: On navigate → Show "Entering" → Auto-transition to "Loaded" after 100ms (500ms Smart Animate)

---

## SECTION I — TECHNICAL SPECIFICATION FOR DEVELOPERS

**If handing off to development, include these technical notes:**

### I.1 — TECH STACK ALIGNMENT

- **Frontend Framework:** React 18+ with TypeScript
- **Styling:** Tailwind CSS 3+ (custom theme config provided in Section B)
- **Animation:** Framer Motion or native CSS animations + IntersectionObserver API
- **Terminal Background:** HTML5 Canvas with requestAnimationFrame
- **State Management:** React Context or Zustand (simple global state)
- **Routing:** React Router v6
- **Forms:** React Hook Form + Zod validation
- **Charts:** Recharts or Chart.js (for admin dashboards)
- **Icons:** Heroicons React

### I.2 — COMPONENT LIBRARY STRUCTURE

**File Organization:**
```
components/
  ui/
    Button.tsx (5 variants)
    Card.tsx (3 variants)
    Input.tsx, Textarea.tsx, Select.tsx
    Badge.tsx (7 severity variants)
    GlitchText.tsx (with pseudo-elements)
    TypewriterText.tsx (CSS animation)
    ScrollReveal.tsx (IntersectionObserver wrapper)
  layout/
    Navbar.tsx
    Footer.tsx
    Container.tsx
    Layout.tsx (wraps all pages)
  home/
    Hero.tsx, Features.tsx, HowItWorks.tsx, etc.
  terminal/
    TerminalBackground.tsx (Canvas component)
```

### I.3 — ANIMATION CONFIG

Create `animationConfig.ts`:
```typescript
export const TIMING = {
  micro: 120,
  hover: 200,
  component: 300,
  pageEnter: 500,
  stagger: 80,
};

export const EASING = {
  default: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)',
  snappy: 'cubic-bezier(0.22, 1, 0.36, 1)',
  decel: 'cubic-bezier(0, 0, 0.2, 1)',
};

export const ANIM_COLORS = {
  green: '#00FF88',
  blue: '#3AA9FF',
  // etc.
};

export function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
```

### I.4 — ACCESSIBILITY REQUIREMENTS

- All interactive elements: keyboard accessible (tab order)
- ARIA labels: Applied to icon-only buttons
- Focus visible: Green ring (ring-2 ring-accent-green ring-offset-2 ring-offset-bg-primary)
- Skip to content link: Hidden but accessible
- Screen reader announcements: Live regions for scan progress
- Reduced motion: All animations disabled if user preference set

---

## ✅ END OF FIGMA AI MASTER PROMPT

**Prompt Summary:**
This document provides complete specifications to recreate the SafeWeb AI frontend design system in Figma AI. Every color, component, animation, layout, and page has been documented with pixel-level precision. The design balances enterprise-grade professionalism with controlled hacker/cybersecurity aesthetic. All requirements are unambiguous and implementation-ready.

**Next Steps for Figma AI:**
1. Create color styles and text styles from Section B
2. Build master components for Button, Card, Input, Badge
3. Design Navbar and Footer (reused across all pages)
4. Construct Landing page following Section E.1
5. Build remaining pages following blueprints in Section E
6. Apply animations/interactions following Section D and H
7. Organize pages, add annotations, create prototyping flow

**Design System Maturity:** Production-ready, enterprise-grade, thesis-defense quality.
