# 1id.com

Hardware-anchored identity registrar for AI agents ("robot passports").
Operational since 2006-05-31T10:30:02Z.

## Git workflow

- **Master repo**: gitolite3 on ca9 (Hurricane Electric, California)
- **Dev machine**: push changes here via `git push`
- **Live server (vaf)**: auto-pulls when ca9 receives a push (via post-receive hook)
- **Web root**: `public_html/` folder is served by nginx on vaf
- **IMPORTANT**: everything in `public_html/` is live on the internet -- do not put secrets there

## Folder layout

```
public_html/          <- nginx document root (public web files)
  index.html          <- main homepage (dark theme, uptime counter, pricing, trust tiers)
  css/style.css       <- stylesheet
  js/main.js          <- live uptime counter, copy-to-clipboard, mobile nav
  .well-known/1id.json <- machine-readable service metadata (JSON)
  llms.txt            <- LLM-friendly plain-text summary
  enroll.md           <- agent enrollment instructions (markdown)
  robots.txt          <- crawler directives
config/               <- server configuration (NOT web-served)
  00-1id-maps.conf    <- nginx map for Accept-header content negotiation
  1id_com_tls.conf    <- nginx TLS server block
api/                  <- FastAPI enrollment API (NOT web-served)
keycloak-spi/         <- Custom Keycloak SPI (protocol mapper + event listener)
deploy.sh             <- deployment script (run by hook on vaf)
readme.md             <- this file
```

## Content negotiation

The root path `/` serves different content based on the HTTP Accept header:
- `Accept: application/json` -> `/.well-known/1id.json`
- `Accept: text/markdown` -> `/enroll.md`
- default -> `/index.html`

This is handled by an nginx `map` directive in `config/00-1id-maps.conf`.


