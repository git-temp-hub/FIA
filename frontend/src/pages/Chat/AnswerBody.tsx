import ReactMarkdown from "react-markdown";

/**
 * Renders an assistant answer as Markdown.
 *
 * Answers follow a fixed FINDING / EVIDENCE / ASSESSMENT / GAPS skeleton and
 * use light Markdown inside it — backticks for process names, paths and PIDs,
 * occasional emphasis, short lists. Rendering it as preformatted text showed
 * the syntax rather than the formatting.
 *
 * Raw HTML is deliberately not enabled. The text is model-generated, and
 * `react-markdown` ignores embedded HTML unless a plugin opts in, which is the
 * behaviour wanted here.
 */
export default function AnswerBody({ content }: { content: string }) {
  return (
    <div className="space-y-3 text-sm leading-relaxed text-slate-100">
      <ReactMarkdown
        components={{
          p: ({ children }) => (
            <p className="break-words text-slate-100">{children}</p>
          ),

          // The four section headings arrive as bare uppercase lines rather
          // than Markdown headings, so these only catch a stray "##".
          h1: ({ children }) => (
            <p className="font-semibold text-white">{children}</p>
          ),
          h2: ({ children }) => (
            <p className="font-semibold text-white">{children}</p>
          ),
          h3: ({ children }) => (
            <p className="font-semibold text-white">{children}</p>
          ),

          ul: ({ children }) => (
            <ul className="list-disc space-y-1 pl-5 text-slate-100">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal space-y-1 pl-5 text-slate-100">
              {children}
            </ol>
          ),
          li: ({ children }) => <li className="pl-1">{children}</li>,

          strong: ({ children }) => (
            <strong className="font-semibold text-white">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-slate-200">{children}</em>
          ),

          code: ({ children }) => (
            <code className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[0.8125rem] text-cyan-300">
              {children}
            </code>
          ),
          pre: ({ children }) => (
            <pre className="overflow-x-auto rounded bg-slate-800 p-3 font-mono text-xs text-slate-200">
              {children}
            </pre>
          ),

          table: ({ children }) => (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                {children}
              </table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border-b border-slate-700 px-2 py-1 font-semibold text-slate-300">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border-b border-slate-800 px-2 py-1 text-slate-200">
              {children}
            </td>
          ),

          hr: () => <hr className="border-slate-700" />,

          // Model-generated links are not part of the evidence-grounding
          // model: an answer cites numbered evidence, never an external URL.
          // Anything that looks like a link renders as plain text.
          a: ({ children }) => <span>{children}</span>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
