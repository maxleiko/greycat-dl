# greycat-dl

```sh
greycat-dl http://localhost:8080 [--outdir /path/to/outdir]
```

## Secured User
Works with `dotenv` (eg. `.env`) files for `username` and `password` if a connected user is required
```env
USERNAME=username
PASSWORD=password
```

> Will initiate a login with the provided `username:password` first, and then give the **token** to the necessary HTTP requests.

## Dry-run
Specifying `--dry-run` will only list files and display the total size in a human-friendly manner:
```sh
greycat-dl http://localhost:8080 --dry-run
```
Would display something like:
```
Listing files from http://localhost:8080/files/
Found 4957 files to download which account for 12.2 GiB
```