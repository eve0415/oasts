let generatedRootUrl;

export function initialize(data) {
  if (typeof data?.generatedRootUrl !== "string") {
    throw new TypeError("generatedRootUrl is required");
  }
  generatedRootUrl = data.generatedRootUrl.endsWith("/")
    ? data.generatedRootUrl
    : `${data.generatedRootUrl}/`;
}

export async function resolve(specifier, context, nextResolve) {
  const parentUrl = context.parentURL;
  const isGeneratedRelativeJs =
    typeof parentUrl === "string" &&
    parentUrl.startsWith(generatedRootUrl) &&
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    specifier.endsWith(".js");

  if (!isGeneratedRelativeJs) {
    return nextResolve(specifier, context);
  }

  try {
    return await nextResolve(specifier, context);
  } catch (originalError) {
    const typescriptSpecifier = `${specifier.slice(0, -3)}.ts`;
    const typescriptUrl = new URL(typescriptSpecifier, parentUrl);
    if (!typescriptUrl.href.startsWith(generatedRootUrl)) {
      throw originalError;
    }
    try {
      return await nextResolve(typescriptSpecifier, context);
    } catch {
      throw originalError;
    }
  }
}
