# Design

This document explains the purpose of `sops-check` and also documents the
functional and non-functional requirements we have, as well as the details
about design decisions we took. It assumes familarity with [SOPS][sops] and the
concepts that it uses.

## Purpose

Check SOPS files for correct and compliant usage without decrypting the SOPS
files to ensure that all SOPS files are configured in the desired fashion. The
goal is to provide a security linter that safeguards the security of the data
protected by the SOPS files against common mistakes and against malicious
configurations.

## Background

SOPS supports encrypting files using one or more "trust anchors" (the
encryption keys used to encrypt a SOPS file). The security of the SOPS file is
primarily governed by the security and selection of suitable. Especially in
enterprise contexts it is important to enforce some rules around the trust
anchors that are in use. Some questions that to be answered could be:

- How can we ensure that any given SOPS file is encrypted using a set of
  required trust anchors?
- How can we detect if non-approved trust anchors are used?
- How can we prevent the usage of certain trust anchors in the presence of
  others (mutual exclusivity)?

To answer these questions for any given SOPS file, `sops-check` needs to be
flexible enough to process a set of user-defined rules which indicate success
or failure.

## Functional Requirements

The high-level functionality of the compliance checker can be summarized like
this:

- Recursively scan a directory tree (such as a Git repository) for SOPS
  encrypted files.
- It should support all file formats supported by SOPS itself.
- Extract trust anchors from SOPS encrypted files to match them against a set
  of user-defined rules.
- Report check results back to the user.

The rules engine needs to support the following functionality:

- Exact matching of a trust anchor ("match")
  - **Example A**: The trust anchor is an AWS KMS Key with the ARN
    `arn:aws:kms:eu-west-1:123456789012:alias/my-team`.
- Matching of a trust anchor via regular expressions ("match regex")
  - **Example B**: The trust anchor matches the regular expression
    `^arn:aws:kms:eu-(central|west)-1:123456789012:.*$`.
- Matching of all rules ("and" / "all of")
  - **Example**: The SOPS file must be encrypted with the AGE disaster recovery
    key as well as the keys of the owner of the file and the deploy key for the
    CI/CD to be able to decrypt it.
- Matching of any rule ("or" / "any of")
  - **Example**: The SOPS file must be encrypted using the key of one or more
    teams responsible for the software component.
- Matching of exactly one rule ("xor" / "one of")
  - **Example**: The trust anchors can only contain the deploy key for
    production **or** staging, but not both, to prevent secret sharing between
    environments.
- Inversion of match behaviour ("not")
  - **Example**: There's an explicit key that should not be part of the trust
    anchors.
- Reject excess trust anchors (not matched by any rule):
  - **Example**: Developers should not be allowed to use additional encryption
    keys apart from the keys managed by the company within any given SOPS file.
    This protects against employees still retaining access to secrets after
    they left the company.

It must be possible to nest these rule arbitrarily deep to allow building
complex match pattern with different dependencies between each other.

## Non-functional Requirements

- The compliance checker should be packaged as a container image for easy
  integration into CI/CD pipelines.

## Design Choices

### Data Model

The data model of the configuration file is formulated as [JSON
schema][config-schema].

This is highly influenced by the [JSON Schema Specification][jsonschema-spec]
itself to allow for great flexibility in the rule composition.

### Configuration Example

Given the following requirements:

- The SOPS file must contain all necessary approved trust anchors:
  - AGE key `age1u79ltfzz5k79ex4mpl3r76p2532xex4mpl3z7vttctudr6gedn6ex4mpl3`
    used for offline disaster recovery.
  - AWS KMS keys of **at least one team** owning the component. Additional team
    keys are allowed, as long as they are part of the list of approved trust
    anchors.
  - AWS KMS keys used for deployment via CI/CD for the target environment
    (staging/production) if the SOPS resides in the `.deploy/**/{environment}/`
    directory.
- AWS KMS keys **must come in pairs** of two different regions to increase availability.
- Any excess trust anchors not matching any of these rules **must be rejected**.

One possible configuration to acheive this could be:

```yaml
---
# All rules must match. This will automatically reject excess trust anchors
# not matching any of the nested rules.
rules:
  - description: Disaster recovery key must be present.
    match: age1u79ltfzz5k79ex4mpl3r76p2532xex4mpl3z7vttctudr6gedn6ex4mpl3
  - anyOf:
      - allOf:
          - match: arn:aws:kms:eu-central-1:123456789012:alias/team-foo
          - match: arn:aws:kms:eu-west-1:123456789012:alias/team-foo
        description: Regional keys of team-foo.
      - allOf:
          - match: arn:aws:kms:eu-central-1:123456789012:alias/team-bar
          - match: arn:aws:kms:eu-west-1:123456789012:alias/team-bar
        description: Regional keys of team-bar.
    description: The AWS KMS key pair of at least one team must be present.
  - allOf:
      - match: arn:aws:kms:eu-central-1:123456789012:alias/production-cicd
      - match: arn:aws:kms:eu-west-1:123456789012:alias/production-cicd
    description: Regional production keys.
    paths:
      - .deploy/**/production/
  - allOf:
      - match: arn:aws:kms:eu-central-1:123456789012:alias/staging-cicd
      - match: arn:aws:kms:eu-west-1:123456789012:alias/staging-cicd
    description: Regional staging keys.
    paths:
      - .deploy/**/staging/
```

### Output

To be as helpful as possible to user, the output should make it clear what the
problem is. It should include information about:

- The SOPS file that failed the compliance check.
- Display information about expected, but missing trust anchors ("any of" / "all of").
- Display information about conflicting trust anchors ("one of").
- Display information about explicitly denied trust anchors ("not").
- Display the trust anchors that did not match any rule.
- Ideally, include context about the line and column in the SOPS file where the
  check failed.
- Optionally provide guidance how to make the file compliant with the rules.

#### Output formats

The compliance checker should support at least textual output intended for
display to users as well as machine readable output in the [SARIF format][sarif].

### Out of Scope

The compliance checker only looks at the trust anchors found in the SOPS
metadata without actually having access to the encryption keys. Because of
that:

- It does not decrypt the contents of the SOPS files.
- It does not check for data corruption within SOPS files. SOPS already does
  this via a MAC signature.
- It does not assess the security of the trust anchors in use. Checking if the
  encryption keys of any of the referenced trust anchors were leaked to the
  internet is out of scope.
- It does not scan the directory tree for plaintext secrets. There are plenty
  of other tools out there that already do this, such as [Gitleaks][gitleaks],
  [Secretlint][secretlint] or [TruffleHog][trufflehog].

## Other Considerations

There are some potential optional features that could be supported by the
compliance checker:

- **Warning mode**: An option to mark certain rules as soft-errors, which emit
  a warning instead of failing the check.
- **Ignore pattern**: Support honoring ignore files, e.g. do not check files
  matching the pattern in `.gitignore`. Another use case may be to explicitly
  exclude certain directories, such as those containing test data.
- **Remote rule lookup**: To manage organization-wide rules it might be useful
  to have the option to read a rules file from a remote location for central
  management.
- **Matching n-of**: Support for matching lists of `m` trust anchors where `n`
  must match the rules, with `n <= m`.
- **Configuration extension**: Support for importing rules from existing
  configuration files into another one.
- **More rule metadata**: A rule configuration could carry more metadata like a
  URL to internal documentation describing the rationale behind it. Other
  options could be tags or keywords to enable better grouping of errors in the
  output based on context.
- **Different rules for different folders**: A rule should match only for specific paths.
  This enables differentiated rules, for example ensure production AWS KMS keys for all
  SOPS files in `/production/` while forbidding production AWS KMS keys for all other paths.
  Need to think about different use cases and allow suitable mixing, for example to ensure
  that the common AGE recovery key is present in all SOPS files, or that no PGP keys are used
  in any SOPS file.

[config-schema]: https://github.com/Bonial-International-GmbH/sops-check/blob/main/schema.json
[gitleaks]: https://github.com/gitleaks/gitleaks
[jsonschema-spec]: https://json-schema.org/draft/2020-12/json-schema-core
[sarif]: https://sarifweb.azurewebsites.net/
[secretlint]: https://github.com/secretlint/secretlint
[sops]: https://github.com/getsops/sops
[trufflehog]: https://github.com/trufflesecurity/trufflehog
