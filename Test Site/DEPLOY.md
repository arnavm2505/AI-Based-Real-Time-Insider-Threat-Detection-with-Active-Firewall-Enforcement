# Deployment Guide

## Step 1 — Initialize Git repo

```bash
cd novatech-auth
git init
git add .
git commit -m "Initial commit: NovaTech auth site"
```

## Step 2 — Push to GitHub

### Option A: GitHub CLI (easiest)
```bash
gh auth login
gh repo create novatech-auth --public --source=. --remote=origin --push
```

### Option B: Manual via github.com
1. Go to https://github.com/new
2. Name it `novatech-auth`, set to Public, don't add README
3. Click "Create repository"
4. Run:
```bash
git remote add origin https://github.com/YOUR_USERNAME/novatech-auth.git
git branch -M main
git push -u origin main
```

## Step 3 — Deploy to Vercel

### Option A: Import from GitHub (recommended)
1. Go to https://vercel.com/new
2. Click "Import Git Repository"
3. Select `novatech-auth`
4. Framework Preset → **Other**
5. Click **Deploy** — done!

### Option B: Vercel CLI
```bash
npm install -g vercel
vercel login
vercel --prod
```
When prompted:
- Set up and deploy? → Y
- Which scope? → your username
- Link to existing project? → N
- Project name? → novatech-auth
- Directory? → ./  (press Enter)
- Override settings? → N

Your live URL will be: https://novatech-auth.vercel.app
