export function visualAssetPath(target, method, assets) {
  if (
    typeof target !== "string" ||
    target.length > 4096 ||
    !["GET", "HEAD"].includes(method)
  )
    return null;
  if (target === "/console/" || target === "/console/setup")
    return "index.html";
  if (target === "/console/favicon.svg") return "favicon.svg";
  const match = /^\/console\/assets\/([A-Za-z0-9_-]+\.(?:js|css))$/.exec(
    target,
  );
  return match && assets.has(match[1]) ? `assets/${match[1]}` : null;
}
