# Data Encryption Standard (synthetic guidance)

Data must be encrypted in transit and at rest. Transport connections use current TLS versions with certificates issued by a trusted authority; legacy protocol versions are disabled.

Encryption keys are generated and stored in a managed key service, rotated at least annually and never embedded in source code or configuration files. Access to keys is logged and limited to named roles.

Backups are encrypted with keys separate from production keys. Restoration is tested every quarter and the result is stored as compliance evidence.
