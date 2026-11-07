# AboutMe

Personal profile site and engineering activity dashboard.

- Dashboard: https://hryknkmr.github.io/aboutme/
- Source data is filtered to allowed owners only.

## Regenerate

```sh
python3 scripts/regenerate_dashboard.py --since <YYYY-MM-DD>
```

Requires an authenticated `gh`. Reads PRs from the allowlisted owners only and rewrites `docs/index.html` and `docs/assets/*-card.svg` in place.
