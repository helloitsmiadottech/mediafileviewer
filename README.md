# Media File Viewer

**Author:** [helloitsmia.tech](https://www.instagram.com/helloitsmia.tech/)

A Chrome extension that detects the file type of mislabled PDF documens and lets you open or preview them with the correct type.

> **Under development.** This is a tool for people who aren’t super technical and want an easier way to view media files that are mislabeled as PDFs on supported document sites. If you’re technical and need to go through lots of files, this is not the most efficient approach; a more programmatic solution (e.g. scripts, APIs) would be better.

**What its for?:** [Watch on Instagram](https://www.instagram.com/reel/DU1yCJ3jxnz/)

---

## Installation

I’m working on getting Media File Viewer into the Chrome Web Store and will update here when it’s available. For now, the best option is to install it as an **unpacked extension** using a release build:

**Download a release:** [v1.0.0](https://github.com/helloitsmiadottech/mediafileviewer/releases/tag/v1.0.0) — download the extension zip from the release’s Assets, then unzip it to a folder on your computer.

### Load the unpacked extension in Chrome

1. Open Chrome and go to `chrome://extensions/`.
2. Turn **Developer mode** on (toggle in the top-right).
3. Click **Load unpacked**.
4. Select the folder where you unzipped the extension (the folder that contains `manifest.json`).
5. The extension should appear in your toolbar; you can pin it from the puzzle icon if needed.

You’ll need to keep that folder in place; removing it or moving it will disable the extension until you load it again.

---

## Supported sites

- justice.gov/epstein/files  
- assets.getkino.com/documents  

## What it does

- **Detect file type** – Uses magic bytes to determine the real format (PDF, video, image, etc.).
- **Open with correct type** – Opens the file in a new tab with the right extension so the browser can display or play it.
- **Video preview** – Paste a video URL to load and preview it in the extension (including MOV via in-browser conversion).

## Feature ideas (contributions welcome)

- Support for more browsers
 Support for more document hosts (configurable or optional).
- Batch “detect and open” for multiple links on a page.
- Download with correct filename/extension from the popup.
- Keyboard shortcut to run detection on the current tab.

**Pull requests are welcome.** If you have ideas or code, open an issue or PR.

## Troubleshooting

If the extension isn’t working, it may be because **age verification has timed out** or the **“I’m not a robot” verification** hasn’t been completed on the site.

- **Reload the page** you’re on (the document or file page).
- On the DOJ site, **verify your age** again if prompted.
- If you’re asked whether you’re a robot, **complete the CAPTCHA**.
- If it still doesn’t work, **clear your browser cache** and try again.

## Questions or feedback?

Reach out on [Instagram](https://www.instagram.com/helloitsmia.tech/) or [Substack](https://helloitsmia.substack.com/).
