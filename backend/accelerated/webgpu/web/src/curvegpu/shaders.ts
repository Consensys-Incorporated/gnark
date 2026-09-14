import { CurveGPUShaderError } from "./errors.js";

let bundledShaders: Record<string, string> | null = null;

/**
 * Install a pre-built shader bundle so the library can operate without
 * making `fetch()` requests for WGSL files.
 *
 * Typically called automatically by importing the generated
 * `shader_bundle.generated.js` file (produced by `npm run build:shaders`).
 * When a bundle is installed, `fetchShaderText` reads from it and only falls
 * back to `fetch()` for paths not present in the bundle.
 */
export function setBundledShaders(bundle: Record<string, string>): void {
  bundledShaders = bundle;
}

export async function fetchShaderText(path: string): Promise<string> {
  const filePath = path.split("#", 1)[0];
  if (bundledShaders) {
    const content = bundledShaders[filePath];
    if (content !== undefined) {
      return content;
    }
  }
  const response = await fetch(filePath);
  if (!response.ok) {
    throw new CurveGPUShaderError(`failed to load shader ${path}: ${response.status} ${response.statusText}`);
  }
  return response.text();
}

export async function fetchShaderPart(spec: string): Promise<string> {
  const [path, fragment] = spec.split("#", 2);
  const text = await fetchShaderText(path);
  if (!fragment) {
    return text;
  }
  const prefix = "section=";
  if (!fragment.startsWith(prefix)) {
    throw new CurveGPUShaderError(`unsupported shader fragment spec: ${spec}`);
  }
  const section = fragment.slice(prefix.length);
  const begin = `// curvegpu:section ${section} begin`;
  const end = `// curvegpu:section ${section} end`;
  const start = text.indexOf(begin);
  if (start < 0) {
    throw new CurveGPUShaderError(`shader section ${section} begin marker not found in ${path}`);
  }
  let bodyStart = start + begin.length;
  if (text[bodyStart] === "\r") {
    bodyStart += 1;
  }
  if (text[bodyStart] === "\n") {
    bodyStart += 1;
  }
  const stop = text.indexOf(end, bodyStart);
  if (stop < 0) {
    throw new CurveGPUShaderError(`shader section ${section} end marker not found in ${path}`);
  }
  return text.slice(bodyStart, stop);
}

export async function fetchShaderParts(parts: readonly string[]): Promise<string> {
  const texts = await Promise.all(parts.map((part) => fetchShaderPart(part)));
  return texts.map((text) => (text.endsWith("\n") ? text : `${text}\n`)).join("");
}
