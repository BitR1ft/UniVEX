"use client";

import React from "react";
import { Card } from "@/components/ui/card";
import { Bot, User, Brain, Wrench, AlertCircle } from "lucide-react";

interface Message {
  id: string;
  type: "user" | "agent" | "thought" | "tool" | "error";
  content: string;
  timestamp: Date;
}

interface MessageBubbleProps {
  message: Message;
}

// ---------------------------------------------------------------------------
// MarkdownContent – simple regex-based renderer (no extra deps)
// ---------------------------------------------------------------------------

interface MarkdownContentProps {
  content: string;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Render a single line's inline markup: bold, italic, inline-code, URLs.
 * Returns a React node array.
 */
function renderInline(text: string): React.ReactNode[] {
  // Token pattern order matters: inline-code > bold > italic > url
  const pattern =
    /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[([^\]]+)\]\((https?:\/\/[^\s)]+)\))|(https?:\/\/\S+)/g;

  const nodes: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    const [full, inlineCode, bold, italic, mdLink, mdLinkText, mdLinkHref, plainUrl] = match;

    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }

    if (inlineCode) {
      nodes.push(
        <code
          key={match.index}
          className="px-1 py-0.5 rounded bg-gray-800 text-cyan-300 font-mono text-[0.8em]"
        >
          {inlineCode.slice(1, -1)}
        </code>
      );
    } else if (bold) {
      nodes.push(
        <strong key={match.index} className="font-bold">
          {bold.slice(2, -2)}
        </strong>
      );
    } else if (italic) {
      nodes.push(
        <em key={match.index} className="italic">
          {italic.slice(1, -1)}
        </em>
      );
    } else if (mdLink) {
      nodes.push(
        <a
          key={match.index}
          href={mdLinkHref}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 underline hover:text-cyan-300 break-all"
        >
          {mdLinkText}
        </a>
      );
    } else if (plainUrl) {
      nodes.push(
        <a
          key={match.index}
          href={plainUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 underline hover:text-cyan-300 break-all"
        >
          {plainUrl}
        </a>
      );
    }

    lastIndex = match.index + full.length;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes;
}

// Table separator row detection — defined as a RegExp constructor (not a regex
// literal) so that Tailwind's content scanner does not misinterpret the
// character-class sequence as an arbitrary-value CSS utility and emit invalid CSS.
const TABLE_SEPARATOR_RE = new RegExp("[\\-:\\s|]", "g");

function isTableSeparatorRow(line: string): boolean {
  return /^\s*\|?[\s:-]+\|/.test(line) && line.replace(TABLE_SEPARATOR_RE, "") === "";
}

/** Parse a pipe-delimited markdown table string into a React table element. */
function renderTable(tableLines: string[], key: number): React.ReactNode {
  const rows = tableLines
    .filter((l) => !isTableSeparatorRow(l))
    .map((l) =>
      l
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((cell) => cell.trim())
    );

  // Detect separator rows to split header from body
  const sepIndex = rows.findIndex((row) => row.every((c) => /^[-:]+$/.test(c)));
  const headerRows = sepIndex > 0 ? rows.slice(0, sepIndex) : [];
  const bodyRows = sepIndex >= 0 ? rows.slice(sepIndex + 1) : rows;

  return (
    <div key={key} className="overflow-x-auto my-2">
      <table className="min-w-full text-xs border border-gray-700 rounded-md overflow-hidden">
        {headerRows.length > 0 && (
          <thead className="bg-gray-800">
            {headerRows.map((row, ri) => (
              <tr key={ri}>
                {row.map((cell, ci) => (
                  <th
                    key={ci}
                    className="px-3 py-1.5 text-left text-gray-300 font-semibold border-b border-gray-700"
                  >
                    {renderInline(cell)}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
        )}
        <tbody>
          {bodyRows.map((row, ri) => (
            <tr key={ri} className={ri % 2 === 0 ? "bg-gray-900" : "bg-gray-950"}>
              {row.map((cell, ci) => (
                <td key={ci} className="px-3 py-1.5 text-gray-400 border-t border-gray-800">
                  {renderInline(cell)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MarkdownContent({ content }: MarkdownContentProps) {
  const nodes: React.ReactNode[] = [];
  const lines = content.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block (``` or ~~~)
    const fenceMatch = line.match(/^(`{3,}|~{3,})\s*(\S*)/);
    if (fenceMatch) {
      const fence = fenceMatch[1];
      const lang = fenceMatch[2] || "";
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith(fence)) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing fence
      nodes.push(
        <div key={`code-${i}`} className="my-2 rounded-md overflow-hidden border border-gray-700">
          {lang && (
            <div className="px-3 py-1 bg-gray-800 text-[10px] font-mono text-cyan-600 border-b border-gray-700">
              {lang}
            </div>
          )}
          <pre className="bg-gray-950 overflow-x-auto p-3 text-xs font-mono text-green-300 leading-relaxed whitespace-pre">
            <code>{codeLines.join("\n")}</code>
          </pre>
        </div>
      );
      continue;
    }

    // Table block — collect consecutive pipe-row lines
    if (/^\s*\|/.test(line)) {
      const tableLines: string[] = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        tableLines.push(lines[i]);
        i++;
      }
      nodes.push(renderTable(tableLines, nodes.length));
      continue;
    }

    // Heading
    const headingMatch = line.match(/^(#{1,6})\s+(.*)/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const text = headingMatch[2];
      const Tag = `h${level}` as keyof JSX.IntrinsicElements;
      const sizeClass =
        level === 1 ? "text-base" : level === 2 ? "text-sm" : "text-xs";
      nodes.push(
        <Tag
          key={`h-${i}`}
          className={`font-bold text-gray-100 mt-3 mb-1 ${sizeClass}`}
        >
          {renderInline(text)}
        </Tag>
      );
      i++;
      continue;
    }

    // Horizontal rule
    if (/^[-*_]{3,}\s*$/.test(line)) {
      nodes.push(<hr key={`hr-${i}`} className="border-gray-700 my-2" />);
      i++;
      continue;
    }

    // Unordered list — collect contiguous bullet lines
    if (/^\s*[-*+]\s/.test(line)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && /^\s*[-*+]\s/.test(lines[i])) {
        const text = lines[i].replace(/^\s*[-*+]\s/, "");
        items.push(
          <li key={i} className="text-gray-400 text-sm">
            {renderInline(text)}
          </li>
        );
        i++;
      }
      nodes.push(
        <ul key={`ul-${i}`} className="list-disc list-inside space-y-0.5 my-1 pl-2">
          {items}
        </ul>
      );
      continue;
    }

    // Ordered list — collect contiguous numbered lines
    if (/^\s*\d+\.\s/.test(line)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && /^\s*\d+\.\s/.test(lines[i])) {
        const text = lines[i].replace(/^\s*\d+\.\s/, "");
        items.push(
          <li key={i} className="text-gray-400 text-sm">
            {renderInline(text)}
          </li>
        );
        i++;
      }
      nodes.push(
        <ol key={`ol-${i}`} className="list-decimal list-inside space-y-0.5 my-1 pl-2">
          {items}
        </ol>
      );
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      const text = line.replace(/^>\s?/, "");
      nodes.push(
        <blockquote
          key={`bq-${i}`}
          className="border-l-2 border-cyan-700 pl-3 my-1 text-gray-500 italic text-sm"
        >
          {renderInline(text)}
        </blockquote>
      );
      i++;
      continue;
    }

    // Blank line — paragraph break
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Regular paragraph line (collect consecutive non-special lines)
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,6}\s|`{3,}|~{3,}|[-*+]\s|\d+\.\s|>\s|[-*_]{3,}|\s*\|)/.test(lines[i])
    ) {
      paraLines.push(lines[i]);
      i++;
    }
    nodes.push(
      <p key={`p-${i}`} className="text-sm text-gray-300 leading-relaxed break-words">
        {paraLines.flatMap((l, li) => [
          ...renderInline(l),
          li < paraLines.length - 1 ? <br key={`br-${li}`} /> : null,
        ])}
      </p>
    );
  }

  return <div className="space-y-1">{nodes}</div>;
}

// ---------------------------------------------------------------------------
// MessageBubble
// ---------------------------------------------------------------------------

export function MessageBubble({ message }: MessageBubbleProps) {
  const getIcon = () => {
    switch (message.type) {
      case "user":
        return <User className="h-5 w-5 text-blue-600" />;
      case "agent":
        return <Bot className="h-5 w-5 text-green-600" />;
      case "thought":
        return <Brain className="h-5 w-5 text-purple-600" />;
      case "tool":
        return <Wrench className="h-5 w-5 text-orange-600" />;
      case "error":
        return <AlertCircle className="h-5 w-5 text-red-600" />;
      default:
        return <Bot className="h-5 w-5" />;
    }
  };

  const getBgColor = () => {
    switch (message.type) {
      case "user":
        return "bg-blue-50 border-blue-200";
      case "agent":
        return "bg-green-50 border-green-200";
      case "thought":
        return "bg-purple-50 border-purple-200";
      case "tool":
        return "bg-orange-50 border-orange-200";
      case "error":
        return "bg-red-50 border-red-200";
      default:
        return "bg-gray-50 border-gray-200";
    }
  };

  const getLabel = () => {
    switch (message.type) {
      case "user":
        return "You";
      case "agent":
        return "Agent";
      case "thought":
        return "Agent Thinking";
      case "tool":
        return "Tool Execution";
      case "error":
        return "Error";
      default:
        return "Message";
    }
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <Card className={`p-4 ${getBgColor()}`}>
      <div className="flex items-start gap-3">
        <div className="mt-1">{getIcon()}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-sm">{getLabel()}</span>
            <span className="text-xs text-muted-foreground">
              {formatTime(message.timestamp)}
            </span>
          </div>
          <div className="prose prose-sm max-w-none dark:prose-invert">
            <MarkdownContent content={message.content} />
          </div>
        </div>
      </div>
    </Card>
  );
}
