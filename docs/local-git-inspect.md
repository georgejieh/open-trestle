# Local Git inspection

`trestle local-git inspect` reads one loose Git commit from an object directory that you name. It checks that the commit, its tree and its files are intact, and it prints a short JSON record of what it found. Use it to confirm that Open Trestle can read a commit before you run a review on it.

```text
trestle local-git inspect \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --revision-digest FULL_LOWERCASE_HEX
```

You must pass every flag, each exactly once. `PATH` is the object directory itself, normally `.git/objects`. The command does not look for a repository, add path components, resolve refs or `HEAD`, read the index or working tree, run Git, read Git configuration, use credentials, or use the network. It does not support packed objects or alternates, so it reads loose objects only.

The repository authority, namespace and name are labels that you supply to describe the scope. They do not establish where the object directory came from, who owns it, or whether anyone is authorized to use it.

## Output

On success the command writes one compact JSON object followed by a newline. The contract is `open-trestle/local-git-inspect-result`, schema version 1, and its strict public shape is `schemas/review/local-git-inspect-result-v1.schema.json`.

The object holds only a structural status, content coverage, and identities. An identity is a digest that stands for one item: the envelope, the repository label, the revision, the adapter, the request, the receipt, the acquisition execution, the profiled acquisition execution, the evidence binding, the manifest, the verified commit, the verified tree graph, the manifest correspondence, or the profile bundle.

The command does not print the object-root path, the repository labels, the raw revision digest, file paths, repository content, profile internals, timestamps, host data or environment data. The status `supplied_evidence_bound` means only that the structure agrees with itself.

## Exit codes

- `0`: the command built and encoded the envelope, closed the object root, and wrote the whole record.
- `1`: an object-root, confinement, loose-object, envelope, profile, close, encoding or output failure.
- `2`: a command grammar failure or an invalid canonical input.

A nonzero exit never comes with a success record.

## What the command proves

The command reads only inside the directory you pass. It checks the hash of every commit, tree and blob it reads with the algorithm you selected, confirms that the whole supported tree matches its manifest, and builds both the structural binding and the repository profile from that single read.

It does not prove that the directory belongs to the repository named by your labels. It also does not prove ownership, authorization, ref reachability, branch state, the state of the working tree or index, snapshot authority, adapter provenance, tenant isolation or sandboxing. It does not review anything, calculate a change, publish, run commands, modify source, or print content.
