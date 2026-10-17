# Scoop manifest

Source of truth for the manifest. On each release the `update-packaging` job
in `.github/workflows/release.yml` fills in the version and hash (with
`scripts/update-packaging.sh`) and pushes `whiff.json` to
[`baoulo/scoop-bucket`](https://github.com/baoulo/scoop-bucket).

```powershell
scoop bucket add baoulo https://github.com/baoulo/scoop-bucket
scoop install whiff
```
