# A collection of rust CLI applications

If I need something I will add it. Currently these are the available applications. To install, run `cargo install --path . --bin <name>`.

## `flux-validator`

Validates that a flux directory is valid for flux. Checks for duplicate document names and finds out what kms keys are being used.

Usage:
```
flux-validator 0.2.3
Validates a direcotory for usage with Flux.

USAGE:
    flux-validator [OPTIONS] [DIR]

ARGS:
    <DIR>    The directory to check

OPTIONS:
    -g, --gen <GEN>        Generate shell completion
    -h, --help             Print help information
        --kms <KMS_ARN>    The KMS ARN [env: SOPS_KMS_ARN=]
    -r, --rotate           Rotate the KMS key
    -V, --version          Print version information
```

Sample output:
```
Duped names
duped documents

kms keys used
kms_keys
└── arn:aws:kms:us-east-1:007640530078:key/b4fc735f-cc01-45ee-b9a1-61d50c9866f1
    ├── ust3/trunk/frameworks/framework-cloudhealth-collector-sops.yml
    └── ust3/trunk/frameworks/framework-provider-binding-namespace-sops.yml
```

Should print out a tree for duplicate names with the conflicting files as leafs.
