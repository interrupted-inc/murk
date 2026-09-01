/**
 * Render delivered secrets as a dotenv file.
 *
 * Values are single-quoted with the standard '\'' escape: safe to `source`
 * from a shell (no expansion of $, backticks, or backslashes) and understood
 * by dotenv parsers. Newlines survive inside single quotes.
 */
export function renderDotenv(entries: ReadonlyArray<readonly [string, string]>): string {
  const lines = [
    "# Delivered by the bb murk plugin. Ephemeral: deleted when the thread goes idle.",
    "# Do not commit this file.",
  ];
  for (const [key, value] of entries) {
    lines.push(`${key}='${value.replaceAll("'", "'\\''")}'`);
  }
  return `${lines.join("\n")}\n`;
}

/** Vault key names are env-var shaped; anything else is refused before murk sees it. */
export const KEY_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
