# Verify commit signatures

Organization-wide rulesets run this action for configured repositories. It verifies every commit introduced by a pull request against the repository's authorized signer groups.

## Manage the policy

1. Add the repository and signer group in [config.py](config.py):

   ~~~python
   "repository-name": RepositoryPolicy(("secops",)),
   ~~~

2. Add each contributor's ASCII-armored **public** primary key at trusted-gpg-keys/<signer-group>/<member>.asc.

   ~~~bash
   gpg --armor --export YOUR_PRIMARY_KEY_FINGERPRINT > member.asc
   ~~~

Never commit secret keys, backups, or revocation certificates. Open a pull request to validate policy and key changes.
