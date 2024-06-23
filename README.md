# windows-authenticode-cert-tagging

Standalone `certificate_tag` tool from https://github.com/google/omaha to modify signed Windows PE and MSI binaries without breaking the signature.

The code is based on a plain copy of the following revision: https://github.com/google/omaha/tree/c3e428cce2af4f8619658b553292147643820219/common/certificate_tag
Some details about the tool's context can be read at the Omaha overview at https://omaha-consulting.com/google-omaha-tutorial-chrome-updater.

The `certificate_tag` tool supports two modes:

1. putting content into the Authenticode signature after the PKCS#7 blob
2. using a "superfluous certificate"

The first mode might not work, if Windows is configured with an enabled `EnableCertPaddingCheck`. See https://learn.microsoft.com/en-us/security-updates/securityadvisories/2014/2915720 for details. The check is opt-in only, so we can assume that the first mode should work on most systems.

## Install

Release artifacts for all popular platforms can be downloaded from https://github.com/gesellix/windows-authenticode-cert-tagging/releases/latest.

A recent Golang version is required if you want to install from source:
```shell
# You should use a specific release like "v0.2.0" instead of "latest".
go install github.com/gesellix/windows-authenticode-cert-tagging/cmd/certificate_tag@latest
```

## Usage

```shell
certificate_tag --help
```
