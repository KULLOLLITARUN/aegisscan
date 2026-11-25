// Node resolver hook for the unit tests: the app imports relative modules without an extension
// (Vite resolves them); Node's ESM loader needs one. Try ".js" for extensionless relative imports.
export async function resolve(specifier, context, next) {
  const relative = specifier.startsWith('./') || specifier.startsWith('../')
  const hasExt = /\.[cm]?[jt]sx?$|\.json$/.test(specifier)
  if (relative && !hasExt) {
    try {
      return await next(`${specifier}.js`, context)
    } catch {
      // fall through to the default resolution and its error message
    }
  }
  return next(specifier, context)
}
