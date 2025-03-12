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
