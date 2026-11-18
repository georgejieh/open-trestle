# Local Git change

`trestle local-git change` compares two loose Git commits that you name and prints a compact JSON record of what changed between them. Use it to see which files a review of the same two commits would cover. It reads loose objects only.

```text
trestle local-git change \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --base-revision-digest FULL_LOWERCASE_HEX \
  --head-revision-digest FULL_LOWERCASE_HEX
```

You must pass all seven flags, each exactly once. `PATH` is the loose-object directory itself, normally `.git/objects`. The base and head revisions are the two commits you choose, in that order. The command does not infer a merge base, resolve refs or `HEAD`, read the index or working tree, look for `.git`, add path components, run Git, read Git configuration, use credentials, or use the network. It does not support packs or alternates.

The repository authority, namespace and name are labels that you supply to describe the scope. They are not checked against the directory.

## Output

The command builds one `open-trestle/local-git-change-result` version 2 JSON object in memory. After it has closed the object root successfully, it writes the object followed by one newline. The schema is `schemas/review/local-git-change-result-v2.schema.json`. Version 1 stays published for the earlier behavior, which supported modified files only.

The object contains only:

- compact identities (digests that stand for the commits, manifests and changes involved) and counts;
- the repository-relative path of each changed file, as documented;
- the kind of change and whether the file is supported or unsupported;
- the reason for each unsupported file;
- for supported files, optional file-change and line-map identities.

It does not contain the object-root path, the repository label text, the raw commit digest, source content, a unified patch, timestamps, host data, environment data, credentials or command output.

Entries follow the canonical path order of the manifest delta. An added text file counts as supported when it is not empty, is valid UTF-8, and is within the size budget. The command compares it against an empty base, so its whole head content is covered. These files remain unsupported, and the record says so: empty files, files with invalid UTF-8 or NUL bytes, files over the diff budget, and removed files.

A supported entry carries authenticated `FileChange` and `LineMap` identities. The aggregate `change` identity covers supported entries only, so the counts and the full entry array are what show partial coverage.

The status is one of:

- `complete`: every changed path is a supported text file.
- `no_change`: the two accepted manifests are equal.
- `partial`: at least one path is supported and at least one is unsupported.
- `unsupported`: paths changed, but none is a supported text file.

Repository-relative paths can be sensitive. The command prints them on purpose, so that a local caller can see which changes it accounted for. Decide where the JSON record may be stored and sent.

## Exit codes

- `0`: the command wrote a complete or no-change record in full.
- `1`: a root, acquisition, graph, resource, encoding, close or output failure.
- `2`: a command grammar failure or an invalid canonical input.
- `3`: the command wrote a partial or unsupported record in full.

Operational and usage failures print no success JSON. The command prepares the output in memory and writes it once, but a low-level output failure can still truncate the stream.

## What the command checks

The command reads only inside the one directory handle it opens. It reads each distinct requested revision once through the same local adapter, so two equal requests cause one read. Each accepted object graph produces a structural binding and a profile. The command processes at most 64 changed paths. Every accepted delta entry produces one opaque supported or unsupported execution, and the source maps are discarded before the command returns.

It does not check that the directory belongs to the repository named by your labels, or ref reachability, ancestry or the state of the working tree. It does not infer renames or copies, report mode-only changes, keep source, review anything, or publish findings.
