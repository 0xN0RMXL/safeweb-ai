# SafeWeb AI - Vercel Deployment Guide

## Prerequisites

1. **GitHub Account** - Your code needs to be in a GitHub repository
2. **Vercel Account** - Sign up at [vercel.com](https://vercel.com)
3. **Project Ready** - Ensure your project builds successfully locally

## Step 1: Prepare Your Project

### 1.1 Test Local Build
```bash
cd "/home/omarammar/Omar/Graduation Project/Safe Web AI Website"
npm run build
```

Verify the build completes without errors. This creates a `dist` folder with your production files.

### 1.2 Test Local Preview
```bash
npm run preview
```

This serves your production build locally to verify everything works.

## Step 2: Push to GitHub

### 2.1 Initialize Git (if not already done)
```bash
cd "/home/omarammar/Omar/Graduation Project/Safe Web AI Website"
git init
git add .
git commit -m "Initial commit - SafeWeb AI project"
```

### 2.2 Create GitHub Repository
1. Go to [github.com](https://github.com)
2. Click the **"+"** icon → **"New repository"**
3. Name it: `safeweb-ai` (or your preferred name)
4. Keep it **Public** or **Private** (your choice)
5. **DO NOT** initialize with README, .gitignore, or license
6. Click **"Create repository"**

### 2.3 Push Your Code
```bash
# Replace YOUR_USERNAME with your GitHub username
git remote add origin https://github.com/YOUR_USERNAME/safeweb-ai.git
git branch -M main
git push -u origin main
```

## Step 3: Deploy to Vercel

### Method 1: Vercel Dashboard (Recommended)

#### 3.1 Sign Up/Login to Vercel
1. Go to [vercel.com](https://vercel.com)
2. Click **"Sign Up"** or **"Login"**
3. Choose **"Continue with GitHub"**
4. Authorize Vercel to access your GitHub repositories

#### 3.2 Import Your Project
1. Click **"Add New..."** → **"Project"**
2. Find your `safeweb-ai` repository in the list
3. Click **"Import"**

#### 3.3 Configure Project
You'll see the configuration screen:

**Framework Preset:** Vite ✅ (Auto-detected)

**Root Directory:** `./` (leave as is)

**Build Settings:**
- Build Command: `npm run build` ✅
- Output Directory: `dist` ✅
- Install Command: `npm install` ✅

**Environment Variables:** None needed for this project

#### 3.4 Deploy
1. Click **"Deploy"**
2. Wait 1-2 minutes for the build to complete
3. You'll see: "🎉 Congratulations!"

Your site will be live at: `https://safeweb-ai-[random].vercel.app`

### Method 2: Vercel CLI (Alternative)

#### 3.1 Install Vercel CLI
```bash
npm install -g vercel
```

#### 3.2 Login to Vercel
```bash
vercel login
```

Follow the prompts to authenticate.

#### 3.3 Deploy
```bash
cd "/home/omarammar/Omar/Graduation Project/Safe Web AI Website"
vercel
```

Follow the prompts:
- Set up and deploy? **Y**
- Which scope? **[Your account]**
- Link to existing project? **N**
- Project name? **safeweb-ai** (or your choice)
- Directory? **./** (press Enter)
- Override settings? **N**

#### 3.4 Deploy to Production
```bash
vercel --prod
```

## Step 4: Custom Domain (Optional)

### 4.1 Add Custom Domain
1. Go to your project dashboard on Vercel
2. Click **"Settings"** → **"Domains"**
3. Enter your domain: `safeweb-ai.com` (example)
4. Click **"Add"**

### 4.2 Configure DNS
Vercel will show you DNS records to add:

**For Root Domain (safeweb-ai.com):**
- Type: `A`
- Name: `@`
- Value: `76.76.21.21`

**For www Subdomain:**
- Type: `CNAME`
- Name: `www`
- Value: `cname.vercel-dns.com`

Add these records in your domain registrar's DNS settings.

### 4.3 Verify Domain
Wait 24-48 hours for DNS propagation (usually faster).
Vercel will automatically issue an SSL certificate.

## Step 5: Environment Configuration

### 5.1 Add Environment Variables (if needed later)
1. Go to **"Settings"** → **"Environment Variables"**
2. Add variables like:
   - `VITE_API_URL` = `https://api.safeweb.ai`
   - `VITE_API_KEY` = `your-api-key`

Note: Prefix all variables with `VITE_` for Vite projects.

### 5.2 Redeploy After Changes
After adding environment variables:
1. Go to **"Deployments"**
2. Click **"..."** on latest deployment
3. Click **"Redeploy"**

## Step 6: Continuous Deployment

### Automatic Deployments
Every time you push to GitHub:
```bash
git add .
git commit -m "Update feature"
git push
```

Vercel automatically:
1. ✅ Detects the push
2. ✅ Builds your project
3. ✅ Deploys to production
4. ✅ Generates a unique preview URL

### Preview Deployments
- **Main branch** → Production deployment
- **Other branches** → Preview deployments
- **Pull requests** → Automatic preview comments

## Step 7: Project Settings

### 7.1 Configure Build & Development
**Settings** → **General:**
- Node.js Version: **18.x** (recommended)
- Framework: **Vite**

### 7.2 Set Up Redirects
Already configured in `vercel.json`:
```json
{
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

This ensures React Router works correctly.

## Troubleshooting

### Build Fails
**Check build logs:**
1. Go to **"Deployments"**
2. Click on failed deployment
3. Review **"Building"** logs

**Common fixes:**
```bash
# Locally test build
npm run build

# Check for TypeScript errors
npm run build 2>&1 | grep "error TS"

# Clear cache and rebuild
rm -rf node_modules package-lock.json
npm install
npm run build
```

### 404 Errors on Routes
Ensure `vercel.json` has the rewrite rule (already added).

### Blank Page After Deploy
**Check browser console:**
- Look for 404 errors on assets
- Verify base URL in `vite.config.ts`

**Fix if needed:**
```typescript
// vite.config.ts
export default defineConfig({
  base: '/', // Ensure this is '/' for Vercel
  // ...
});
```

### Slow Build Times
**Optimize build:**
1. **Settings** → **General** → **Build & Development Settings**
2. Add build optimization flags:
   - Build Command: `npm run build -- --mode production`

## Production Checklist

Before going live:
- ✅ Test all pages and routes
- ✅ Verify mobile responsiveness
- ✅ Check browser console for errors
- ✅ Test forms and interactions
- ✅ Verify links in navigation
- ✅ Enable analytics (Vercel Analytics)
- ✅ Set up custom domain
- ✅ Configure SSL/HTTPS (automatic)
- ✅ Add meta tags for SEO
- ✅ Test performance (Lighthouse)

## Useful Vercel Commands

```bash
# Deploy to preview
vercel

# Deploy to production
vercel --prod

# List deployments
vercel list

# View logs
vercel logs [deployment-url]

# Remove project
vercel remove [project-name]

# Pull environment variables
vercel env pull
```

## Monitoring & Analytics

### Enable Vercel Analytics
1. Go to **"Analytics"** tab
2. Click **"Enable Analytics"**
3. Free tier includes:
   - Real user monitoring
   - Core Web Vitals
   - Audience insights

### Enable Vercel Speed Insights
1. Install package:
```bash
npm install @vercel/speed-insights
```

2. Add to `src/main.tsx`:
```typescript
import { SpeedInsights } from "@vercel/speed-insights/react"

// In your root component
<SpeedInsights />
```

## Cost Breakdown

**Hobby Plan (Free):**
- ✅ Unlimited deployments
- ✅ 100 GB bandwidth/month
- ✅ Custom domains
- ✅ Automatic HTTPS
- ✅ Preview deployments
- ✅ Git integration

**Pro Plan ($20/month):**
- Everything in Hobby
- Commercial use
- Advanced analytics
- Priority support
- 1TB bandwidth

## Support & Resources

- **Documentation:** [vercel.com/docs](https://vercel.com/docs)
- **Community:** [github.com/vercel/vercel/discussions](https://github.com/vercel/vercel/discussions)
- **Support:** [vercel.com/support](https://vercel.com/support)
- **Status:** [vercel-status.com](https://vercel-status.com)

---

## Quick Start Summary

1. **Build locally:** `npm run build`
2. **Push to GitHub**
3. **Go to [vercel.com](https://vercel.com)**
4. **Import repository**
5. **Click Deploy**
6. **Done! 🚀**

Your SafeWeb AI project will be live in minutes at:
`https://safeweb-ai-[random].vercel.app`

You can then add a custom domain if needed.
