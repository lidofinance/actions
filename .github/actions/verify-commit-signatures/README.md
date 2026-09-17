# Verify commit signatures

Organization-wide rulesets run this action to verify every commit introduced by a pull request. Every non-GitHub ASCII-armored public key in `trusted-gpg-keys` is authorized for every repository that uses the action.

GitHub web-flow signatures are not contributor signatures: they are accepted only on reproducible, clean two-parent merges. Every other introduced commit must have a valid signature from a trusted contributor key.

## Add a trusted key

1. Add each contributor's ASCII-armored **public** primary key at `trusted-gpg-keys/<group>/<member>.asc`. Groups organize keys but do not affect authorization.

   ~~~bash
   gpg --armor --export YOUR_PRIMARY_KEY_FINGERPRINT > member.asc
   ~~~

Never commit secret keys, backups, or revocation certificates. Open a pull request to validate key changes.
