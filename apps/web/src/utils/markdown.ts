/**
 * Safe, Zero-Dependency Markdown Renderer (ZK-065).
 *
 * Implements a lightweight, XSS-safe Markdown-to-HTML parser.
 * All raw HTML characters are escaped first to prevent code injection.
 */

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function sanitizeUrl(url: string): string {
  const trimmed = url.trim();
  if (
    trimmed.startsWith("http://") ||
    trimmed.startsWith("https://") ||
    trimmed.startsWith("/") ||
    trimmed.startsWith("#")
  ) {
    return trimmed;
  }
  return "#";
}

export function renderMarkdown(markdown: string): string {
  if (!markdown) return "";

  // Normalize line endings
  const source = markdown.replace(/\r\n/g, "\n");
  const lines = source.split("\n");
  const out: string[] = [];

  let inCodeBlock = false;
  let codeBlockLines: string[] = [];
  let inList: "ul" | "ol" | null = null;
  let inBlockquote = false;
  let blockquoteLines: string[] = [];

  const flushList = () => {
    if (inList) {
      out.push(inList === "ul" ? "</ul>" : "</ol>");
      inList = null;
    }
  };

  const flushBlockquote = () => {
    if (inBlockquote) {
      out.push(`<blockquote>${renderInline(blockquoteLines.join("<br/>"))}</blockquote>`);
      inBlockquote = false;
      blockquoteLines = [];
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]!;
    const trimmed = rawLine.trim();

    // Code block toggle (```)
    if (trimmed.startsWith("```")) {
      if (inCodeBlock) {
        out.push(
          `<pre><code class="code-block">${escapeHtml(codeBlockLines.join("\n"))}</code></pre>`
        );
        codeBlockLines = [];
        inCodeBlock = false;
      } else {
        flushList();
        flushBlockquote();
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockLines.push(rawLine);
      continue;
    }

    // Empty line resets block elements
    if (trimmed === "") {
      flushList();
      flushBlockquote();
      continue;
    }

    // Blockquote
    if (trimmed.startsWith(">")) {
      flushList();
      inBlockquote = true;
      blockquoteLines.push(escapeHtml(trimmed.slice(1).trim()));
      continue;
    } else {
      flushBlockquote();
    }

    // Horizontal rule
    if (/^(---|\*\*\*|___)$/.test(trimmed)) {
      flushList();
      out.push("<hr/>");
      continue;
    }

    // Headings
    if (trimmed.startsWith("# ")) {
      flushList();
      out.push(`<h1>${renderInline(escapeHtml(trimmed.slice(2)))}</h1>`);
      continue;
    }
    if (trimmed.startsWith("## ")) {
      flushList();
      out.push(`<h2>${renderInline(escapeHtml(trimmed.slice(3)))}</h2>`);
      continue;
    }
    if (trimmed.startsWith("### ")) {
      flushList();
      out.push(`<h3>${renderInline(escapeHtml(trimmed.slice(4)))}</h3>`);
      continue;
    }
    if (trimmed.startsWith("#### ")) {
      flushList();
      out.push(`<h4>${renderInline(escapeHtml(trimmed.slice(5)))}</h4>`);
      continue;
    }

    // Unordered list (- or *)
    if (/^[-*]\s+/.test(trimmed)) {
      if (inList !== "ul") {
        flushList();
        out.push("<ul>");
        inList = "ul";
      }
      const itemText = trimmed.replace(/^[-*]\s+/, "");
      out.push(`<li>${renderInline(escapeHtml(itemText))}</li>`);
      continue;
    }

    // Ordered list (1. 2. etc)
    if (/^\d+\.\s+/.test(trimmed)) {
      if (inList !== "ol") {
        flushList();
        out.push("<ol>");
        inList = "ol";
      }
      const itemText = trimmed.replace(/^\d+\.\s+/, "");
      out.push(`<li>${renderInline(escapeHtml(itemText))}</li>`);
      continue;
    }

    // Regular paragraph
    flushList();
    out.push(`<p>${renderInline(escapeHtml(trimmed))}</p>`);
  }

  flushList();
  flushBlockquote();
  if (inCodeBlock) {
    out.push(`<pre><code class="code-block">${escapeHtml(codeBlockLines.join("\n"))}</code></pre>`);
  }

  return out.join("\n");
}

/**
 * Parses inline Markdown formatting: bold, italic, code, links.
 */
function renderInline(escapedText: string): string {
  let result = escapedText;

  // Inline code: `code`
  result = result.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

  // Bold: **text** or __text__
  result = result.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  result = result.replace(/__([^_]+)__/g, "<strong>$1</strong>");

  // Italic: *text* or _text_
  result = result.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  result = result.replace(/_([^_]+)_/g, "<em>$1</em>");

  // Links: [text](url)
  result = result.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, text, url) => {
    const safeUrl = sanitizeUrl(url);
    return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${text}</a>`;
  });

  return result;
}
