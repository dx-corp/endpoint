#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const NAMES = new Set(["endpoint", "private-runner", "private-deployment", "api", "examples", "plugins", "capobara"]);
const SHA = /^[0-9a-f]{40}$/;
const HEX = /^[0-9a-f]{64}$/;
// `toolDigest` is the one provenance field with two legitimate shapes. Node
// hashes the contents of its own TOOL_INPUTS script list, giving a 64-hex
// SHA-256; Capobara embeds the git tree id of `rust/tools/capobara`, giving a
// 40-hex object name. Both are valid "the tool that ran this matches the tool
// committed at this revision" proofs, and the Rust side's
// `git::is_tree_id_or_digest` accepts both widths for exactly this reason --
// this predicate is its twin and must stay in step with it. A receipt written
// by either implementation has to validate here, or a clone of
// `dx-corp/capobara` fails `invalid provenance toolDigest` against a
// perfectly correct tree.
const TOOL_DIGEST = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const PROTO = ["deixicpublic/v1/sdk.proto"];
const SKILLS = [
  "doc-coauthoring", "frontend-design", "incident-triage", "install-code-review", "mcp-builder",
  "openai-agent-browser-verify", "pr-review", "release-verification", "security-review", "skill-creator",
  "webapp-testing",
].sort();

function requireValue(condition, reason) { if (!condition) throw new Error(reason); }
function exactKeys(value, expected, label) {
  requireValue(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  requireValue(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()), `${label} has unexpected or missing keys`);
}
function run(command, args, cwd, env = {}) {
  return execFileSync(command, args, {
    cwd, env: { ...process.env, ...env }, encoding: "utf8", timeout: 300000, maxBuffer: 64 * 1024 * 1024,
  });
}

export async function treeFiles(root) {
  const files = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      requireValue(!entry.isSymbolicLink(), `symlinks are forbidden: ${relative(root, path)}`);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(relative(root, path).split("\\").join("/"));
      else throw new Error(`special files are forbidden: ${relative(root, path)}`);
    }
  }
  await visit(root);
  return files.sort();
}

export async function validateSafeTree(name, root) {
  const files = await treeFiles(root);
  requireValue(files.includes("LICENSE"), "projected source license is missing");
  const forbidden = [
    /(^|\/)AGENTS\.md$/, /(^|\/)\.env(?:\.|$)/, /(^|\/)(?:id_rsa|id_ed25519|gha-creds-[^/]+\.json)$/,
    /(^|\/)tools\/session-history(?:\/|$)/, /(^|\/)config\/maestro-product-template(?:\/|$)/,
  ];
  for (const path of files) {
    for (const pattern of forbidden) requireValue(!pattern.test(path), `forbidden public path: ${path}`);
    if (path.startsWith(".agents/")) requireValue(name === "plugins" && path === ".agents/plugins/marketplace.json", `forbidden .agents path: ${path}`);
    if (/\.(?:json|ya?ml|toml|md|mjs|js|ts|py|rs|sh|proto|swift|plist)$/i.test(path)) {
      const bytes = await readFile(join(root, path));
      if (bytes.length <= 8 * 1024 * 1024) {
        const text = bytes.toString("utf8");
        requireValue(!/^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/m.test(text), `private key found: ${path}`);
        requireValue(!/(?:ghp|github_pat)_[A-Za-z0-9_]{20,}/.test(text), `GitHub token found: ${path}`);
      }
    }
  }
  return files;
}

export async function validateApiDocLinks(root, files) {
  for (const file of files.filter(path => path.endsWith(".md"))) {
    const source = await readFile(join(root, file), "utf8");
    const links = [...source.matchAll(/\]\(([^\s)]+)(?:\s+"[^"]*")?\)/g)]
      .map(match => ({ target: match[1], base: dirname(join(root, file)) }));
    const sourcePaths = [...source.matchAll(/(?<![A-Za-z0-9_./-])(?:sdk\/deixic|contracts|proto)\/[A-Za-z0-9_./-]+/g)]
      .map(match => ({ target: match[0], base: root }));
    for (const { target, base } of [...links, ...sourcePaths]) {
      if (/^(?:[a-z][a-z0-9+.-]*:|\/|#)/i.test(target)) continue;
      const pathname = decodeURIComponent(target.split(/[?#]/, 1)[0]);
      const resolved = resolve(base, pathname);
      const path = relative(root, resolved).split("\\").join("/");
      requireValue(path && !path.startsWith("../") && path !== ".." && files.includes(path),
        `broken API documentation link: ${file} -> ${target}`);
    }
  }
}

export async function validateProvenance(name, root) {
  const provenance = JSON.parse(await readFile(join(root, ".repository-projection.json"), "utf8"));
  exactKeys(provenance, [
    "schemaVersion", "projection", "projectionSchemaVersion", "sourceRepository", "sourceSha",
    "destinationRepository", "priorProjectedBase", "definitionDigest", "toolDigest", "contentDigest",
    "publicationEligible",
  ], "projection provenance");
  requireValue(provenance.schemaVersion === 1 && provenance.projectionSchemaVersion === 1, "unsupported provenance schema");
  requireValue(provenance.projection === name && provenance.sourceRepository === "dx-corp/mono"
    && provenance.destinationRepository === `dx-corp/${name}`, "projection provenance identity mismatch");
  requireValue(SHA.test(provenance.sourceSha) && SHA.test(provenance.priorProjectedBase), "projection SHAs are invalid");
  for (const key of ["definitionDigest", "contentDigest"]) requireValue(HEX.test(provenance[key]), `invalid provenance ${key}`);
  requireValue(TOOL_DIGEST.test(provenance.toolDigest), "invalid provenance toolDigest");
  requireValue(typeof provenance.publicationEligible === "boolean", "invalid publication eligibility");
  return provenance;
}

async function validateEndpoint(root, files) {
  for (const required of ["Cargo.toml", "Cargo.lock", "merlin/Cargo.toml", "merlin-common/Cargo.toml",
    "merlin-ebpf/Cargo.toml", "packaging/linux/test-packaging.sh", "rules/block-demo.yaml",
    "packs/sigma-linux.yaml", "macos/Package.swift"]) {
    requireValue(files.includes(required), `endpoint is missing ${required}`);
  }
  for (const path of files) requireValue(!/^(?:server|admin-ui|tools)(?:\/|$)|^Dockerfile$|^macos\/docs\//.test(path), `endpoint contains an internal surface: ${path}`);
  const metadata = JSON.parse(run("cargo", ["metadata", "--no-deps", "--locked", "--format-version", "1"], root));
  requireValue(metadata.workspace_members.length === 2 && metadata.packages.every(pkg => ["merlin", "merlin-common"].includes(pkg.name)), "endpoint Cargo workspace closure changed");
  const ebpf = await readFile(join(root, "merlin-ebpf", "Cargo.toml"), "utf8");
  requireValue(/merlin-common\s*=\s*\{\s*path\s*=\s*"\.\.\/merlin-common"\s*\}/.test(ebpf), "endpoint eBPF path closure changed");
  run("cargo", ["test", "--locked", "-p", "merlin-common"], root);
  if (process.platform === "linux") run("sh", ["packaging/linux/test-packaging.sh"], root);
  else {
    for (const script of ["build-package.sh", "install.sh", "merlin-launcher.sh", "test-packaging.sh", "uninstall.sh"]) {
      run("sh", ["-n", `packaging/linux/${script}`], root);
    }
    run("python3", ["packaging/linux/release-attestation.py", "--help"], root);
  }
}

async function validateRunner(root, files) {
  for (const required of ["render.mjs", "runner-host-contract.json", "verify-image.sh", "examples/profile.json", "tests/render.test.mjs"]) requireValue(files.includes(required), `private runner is missing ${required}`);
  run("node", ["--test", "tests/render.test.mjs"], root);
  run("node", ["render.mjs", "--profile", "examples/profile.json"], root);
  run("sh", ["-n", "verify-image.sh"], root);
}

async function validateDeployment(root, files) {
  for (const required of ["verify-bundle.mjs", "import-bundle.mjs", "validate-charts.mjs", "tests/bundle.test.mjs"]) requireValue(files.includes(required), `private deployment is missing ${required}`);
  run("node", ["validate-charts.mjs"], root);
  run("node", ["--test", "tests/bundle.test.mjs"], root);
}

async function validateApi(root, files) {
  await validateApiDocLinks(root, files);
  requireValue(files.includes("scripts/contracts/normalize-openapi-generated.py"), "API OpenAPI normalizer is missing");
  const actualProto = files.filter(path => path.startsWith("proto/") && path.endsWith(".proto")).map(path => path.slice(6)).sort();
  requireValue(JSON.stringify(actualProto) === JSON.stringify(PROTO), "API protobuf allowlist differs from the public SDK closure");
  const expectedOpenapi = PROTO.map(path => path.replace(/\.proto$/, ".openapi.yaml"));
  const actualOpenapi = files.filter(path => path.startsWith("openapi/") && path.endsWith(".openapi.yaml")).map(path => path.slice(8)).sort();
  requireValue(JSON.stringify(actualOpenapi) === JSON.stringify(expectedOpenapi), "API OpenAPI allowlist differs from the protobuf closure");
  const projectedOpenapi = new Map(await Promise.all(expectedOpenapi.map(async path =>
    [path, await readFile(join(root, "openapi", path))]
  )));
  for (const path of actualProto) {
    const text = await readFile(join(root, "proto", path), "utf8");
    for (const match of text.matchAll(/^import\s+"([^"]+)";/gm)) {
      const imported = match[1];
      if (imported.startsWith("google/") || imported === "buf/validate/validate.proto") continue;
      requireValue(PROTO.includes(imported), `unresolved local protobuf import: ${path} -> ${imported}`);
    }
  }
  const surface = JSON.parse(await readFile(join(root, "contracts", "public-surface.json"), "utf8"));
  requireValue(surface.service === "deixicpublic.v1.DeixicPublicService" && surface.operations?.length === 8, "Deixic public facade contract changed");
  const rpcs = surface.operations.map(item => item.rpc).sort();
  requireValue(new Set(rpcs).size === 8 && surface.operations.filter(item => item.kind === "mutation").every(item => item.requiresIdempotencyKey), "Deixic public operations are invalid");
  const generation = await readFile(join(root, "buf.gen.yaml"), "utf8");
  requireValue(generation.includes("sudorandom-connect-openapi:v0.19.1") && !generation.includes("./scripts/"), "public codegen config is not pinned or is private");
  run("buf", ["build"], root);
  run("buf", ["lint"], root);
  const generatedRoot = await mkdtemp(join(tmpdir(), "api-openapi-validation-"));
  try {
    run("buf", ["generate", "--output", generatedRoot], root);
    const generatedOpenapiRoot = join(generatedRoot, "openapi");
    run("python3", ["scripts/contracts/normalize-openapi-generated.py", generatedOpenapiRoot], root);
    const generatedOpenapi = await treeFiles(generatedOpenapiRoot);
    requireValue(JSON.stringify(generatedOpenapi) === JSON.stringify(expectedOpenapi), "Buf generation output differs from the public API closure");
    for (const path of expectedOpenapi) {
      const generated = await readFile(join(generatedOpenapiRoot, path));
      requireValue(generated.equals(projectedOpenapi.get(path)), `projected OpenAPI is stale: ${path}`);
    }
  } finally {
    await rm(generatedRoot, { recursive: true, force: true });
  }
}

async function validateExamples(root, files) {
  for (const required of ["examples/account-brief.mjs", "examples/account-brief-result.mjs",
    "python/deixic_examples/account_brief.py", "python/deixic_examples/account_brief_result.py",
    "test/account-brief-result.test.mjs", "test/test_python_result.py"]) requireValue(files.includes(required), `examples is missing ${required}`);
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  requireValue(pkg.private === true && !pkg.dependencies, "examples package must not claim an unavailable registry dependency");
  const versions = JSON.parse(await readFile(join(root, "sdk-versions.json"), "utf8"));
  exactKeys(versions, ["typescript", "python"], "example SDK versions");
  exactKeys(versions.typescript, ["package", "version"], "example TypeScript SDK version");
  exactKeys(versions.python, ["package", "version"], "example Python SDK version");
  const exactVersion = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
  requireValue(versions.typescript.package === "@evalops/deixic-sdk" && exactVersion.test(versions.typescript.version)
    && versions.python.package === "deixic-sdk" && exactVersion.test(versions.python.version), "example SDK versions are not exact pins");
  run("node", ["--test", "test/account-brief-result.test.mjs"], root);
  run("node", ["--check", "examples/account-brief.mjs"], root);
  run("python3", ["-m", "unittest", "discover", "-s", "test", "-p", "test_*.py"], root, { PYTHONDONTWRITEBYTECODE: "1" });
  run("python3", ["-c", "import ast,pathlib; [ast.parse(p.read_text(), filename=str(p)) for p in pathlib.Path('python').rglob('*.py')]"], root, { PYTHONDONTWRITEBYTECODE: "1" });
  const nodePackage = process.env.DEIXIC_EXAMPLES_NODE_PACKAGE;
  const pythonWheel = process.env.DEIXIC_EXAMPLES_PYTHON_WHEEL;
  requireValue(nodePackage && pythonWheel, "examples validation requires exact SDK package artifacts from the Mono SDK projections");
  requireValue((await lstat(nodePackage)).isFile() && nodePackage.endsWith(".tgz"), "invalid Deixic Node package artifact");
  requireValue((await lstat(pythonWheel)).isFile() && pythonWheel.endsWith(".whl"), "invalid Deixic Python wheel artifact");
  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-save", "--package-lock=false", nodePackage], root);
  run("node", ["--input-type=module", "-e",
    `import { readFile } from "node:fs/promises"; const p=JSON.parse(await readFile("node_modules/@evalops/deixic-sdk/package.json")); if(p.version!==${JSON.stringify(versions.typescript.version)}) process.exit(1);`], root);
  const cleanEnvironment = { ...process.env };
  for (const key of ["DEIXIC_API_KEY", "DEIXIC_ORGANIZATION_ID", "DEIXIC_WORKSPACE_ID", "DEIXIC_BASE_URL"])
    delete cleanEnvironment[key];
  const nodeCheck = spawnSync("node", ["examples/account-brief.mjs", "check"], {
    cwd: root, env: cleanEnvironment, encoding: "utf8", timeout: 30000,
  });
  requireValue(nodeCheck.status === 1, "TypeScript example no-credential check did not fail closed");
  const nodeResult = JSON.parse(nodeCheck.stdout);
  requireValue(nodeResult.status === "error" && nodeResult.kind === "configuration", "TypeScript example returned an unexpected check result");
  const virtualEnvironment = join(root, ".example-validation-venv");
  run("python3", ["-m", "venv", virtualEnvironment], root);
  const installedPython = join(virtualEnvironment, process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  run(installedPython, ["-m", "pip", "install", "--disable-pip-version-check", pythonWheel], root);
  run(installedPython, ["-c", `import importlib.metadata as m; assert m.version("deixic-sdk") == ${JSON.stringify(versions.python.version)}`], root);
  const pythonCheck = spawnSync(installedPython, ["-m", "python.deixic_examples.account_brief", "check"], {
    cwd: root, env: { ...cleanEnvironment, PYTHONDONTWRITEBYTECODE: "1", PYTHONPATH: root }, encoding: "utf8", timeout: 30000,
  });
  requireValue(pythonCheck.status === 1, "Python example no-credential check did not fail closed");
  const pythonResult = JSON.parse(pythonCheck.stdout);
  requireValue(pythonResult.status === "error" && pythonResult.kind === "configuration", "Python example returned an unexpected check result");
}

async function validatePlugins(root, files) {
  const catalog = JSON.parse(await readFile(join(root, ".agents", "plugins", "marketplace.json"), "utf8"));
  exactKeys(catalog, ["name", "interface", "plugins"], "marketplace");
  requireValue(catalog.name === "deixic" && catalog.interface?.displayName === "Deixic" && catalog.plugins?.length === 1, "invalid marketplace identity");
  const entry = catalog.plugins[0];
  exactKeys(entry, ["name", "source", "policy", "category"], "marketplace plugin");
  requireValue(entry.name === "deixic-code-skills" && entry.source?.source === "local"
    && entry.source?.path === "./plugins/deixic-code-skills", "marketplace source is invalid");
  requireValue(entry.policy?.installation === "AVAILABLE" && entry.policy?.authentication === "ON_INSTALL"
    && Object.keys(entry.policy).length === 2 && entry.category === "Developer Tools", "marketplace policy is invalid");
  const pluginRoot = join(root, "plugins", "deixic-code-skills");
  const manifest = JSON.parse(await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"));
  requireValue(manifest.name === "deixic-code-skills" && /^\d+\.\d+\.\d+$/.test(manifest.version)
    && manifest.skills === "./skills/" && manifest.license === "BUSL-1.1", "plugin manifest is invalid");
  requireValue(Array.isArray(manifest.interface?.defaultPrompt) && manifest.interface.defaultPrompt.length <= 3
    && manifest.interface.defaultPrompt.every(item => typeof item === "string" && item.length <= 128), "plugin starter prompts are invalid");
  const skillDirectories = (await readdir(join(pluginRoot, "skills"), { withFileTypes: true }))
    .filter(entryValue => entryValue.isDirectory()).map(entryValue => entryValue.name).sort();
  requireValue(JSON.stringify(skillDirectories) === JSON.stringify(SKILLS), "plugin skill allowlist changed");
  const declaredSkillNames = new Set();
  for (const skill of SKILLS) {
    const text = await readFile(join(pluginRoot, "skills", skill, "SKILL.md"), "utf8");
    const declared = text.match(/^name:\s*([a-z][a-z0-9-]*)\s*$/m)?.[1];
    requireValue(text.startsWith("---\n") && declared && !declaredSkillNames.has(declared)
      && /^description:\s*\S/m.test(text), `invalid skill metadata: ${skill}`);
    declaredSkillNames.add(declared);
  }
  requireValue(files.includes("plugins/deixic-code-skills/LICENSE"), "plugin license is missing");
  for (const path of files) requireValue(!/(?:prompt-audit|session-history|product-kit)/i.test(path), `private plugin surface: ${path}`);
}

// `capobara` is admitted here like every other catalog entry: `validate.mjs`
// admits any name the catalog holds, and the `sync` job validates every
// prepared projection between Capobara's dry run and its real run, so a
// catalog entry with no validator here fails its publication on
// `unsupported distribution: capobara`.
//
// The compile proof for the projected crate lives in the crate's own
// `tests/standalone_build.rs`, which copies it out of the workspace and runs
// `cargo build --locked`. Repeating that here would add a full dependency
// build to every catalog verification, so this checks the standalone
// closure without compiling: the manifest, the crate-root lockfile and the
// single-package workspace that the projection has to produce, plus the
// internal surfaces it must not carry.
async function validateCapobara(root, files) {
  for (const required of ["Cargo.toml", "Cargo.lock", "README.md", "build.rs", "src/main.rs", "src/lib.rs"]) {
    requireValue(files.includes(required), `capobara is missing ${required}`);
  }
  for (const path of files) {
    requireValue(!/^scripts\//.test(path), `capobara contains an internal surface: ${path}`);
    requireValue(!/^tests\/fixtures\/definitions\//.test(path), `capobara contains an excluded fixture: ${path}`);
  }
  const manifest = await readFile(join(root, "Cargo.toml"), "utf8");
  requireValue(!/\bworkspace\s*=\s*true/.test(manifest), "capobara Cargo.toml still inherits from the Mono workspace");
  // Resolution must include dependencies here: with `--no-deps` nothing is
  // resolved, so `--locked` has nothing to compare and a stale lockfile
  // passes. With the full graph, `--locked` fails when the projected
  // crate-root lockfile does not match the projected manifest, which is the
  // failure this projection is most exposed to -- the standalone lockfile is
  // generated separately from the workspace one and can go stale without any
  // Mono build noticing.
  //
  // This resolves all 178 locked packages, so on a cold runner it fetches the
  // crates.io index and downloads every `.crate`. That is a network-dependent
  // step in the component's CI gate; the component already declares `rust` in
  // `ci.test.tools`, and nothing cheaper discriminates (see above).
  const metadata = JSON.parse(run("cargo", ["metadata", "--locked", "--format-version", "1"], root));
  requireValue(metadata.workspace_members.length === 1, "capobara standalone workspace gained a member");
  const member = metadata.packages.find(pkg => pkg.id === metadata.workspace_members[0]);
  requireValue(member?.name === "capobara", "capobara standalone workspace member is not the crate");
}

export async function validateDistribution({ name, target }) {
  requireValue(NAMES.has(name), `unsupported distribution: ${name}`);
  const root = resolve(target);
  requireValue((await lstat(root)).isDirectory(), "target must be a directory");
  const files = await validateSafeTree(name, root);
  await validateProvenance(name, root);
  const validators = {
    endpoint: validateEndpoint, "private-runner": validateRunner, "private-deployment": validateDeployment,
    api: validateApi, examples: validateExamples, plugins: validatePlugins, capobara: validateCapobara,
  };
  await validators[name](root, files);
  return { name, target: root, files: files.length, valid: true };
}

async function main() {
  const { values, positionals } = parseArgs({ options: { name: { type: "string" }, target: { type: "string" } }, allowPositionals: true });
  requireValue(positionals.length === 0 && values.name && values.target,
    "usage: node scripts/projections/distribution-validation.mjs --name <name> --target <prepared destination>");
  process.stdout.write(JSON.stringify(await validateDistribution({ name: values.name, target: values.target })) + "\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try { await main(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
