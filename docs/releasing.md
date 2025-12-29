# Releasing

- Update codes.
- Update versions of imported packages in [deno.json](../deno.json)
- Check codes:

  ```bash
  rm deno.lock

  deno check
  deno lint
  deno check *.ts
  deno test
  ```
- Commit and push without increasing the version.
- Test in test environments.
- Test in production environments.
- Update the version in [deno.json](../deno.json)
- Commit and push.
