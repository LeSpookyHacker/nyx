import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { clsx } from 'clsx'
import DOMPurify from 'dompurify'
import { safeUrl } from '../../utils/url'

interface Props {
  children: string
  className?: string
  /** Use 'sm' for sidebar/compact contexts, 'base' (default) for main content areas */
  size?: 'sm' | 'base'
}

/** Returns true if content looks like HTML rather than plain text or markdown. */
function isHtml(content: string): boolean {
  return /<[a-z][\s\S]*?>/i.test(content.trimStart().slice(0, 200))
}

/**
 * Sanitize scanner-sourced or AI-generated HTML using DOMPurify (SEC-001).
 * DOMPurify uses a DOM-based allowlist approach — far stronger than regex
 * blocklisting, which has well-known bypasses (SVG events, form actions,
 * data URIs, style-based injection, etc.).
 */
function sanitize(html: string): string {
  return DOMPurify.sanitize(html)
}

/**
 * Renders AI-generated markdown or scanner-sourced HTML with Nyx dark-theme
 * styling. Detects HTML automatically and sanitizes before rendering.
 * Handles GFM: tables, task lists, strikethrough.
 */
export default function MarkdownContent({ children, className, size = 'base' }: Props) {
  const prose = size === 'sm' ? 'text-xs' : 'text-sm'

  if (isHtml(children)) {
    return (
      <div
        className={clsx('nyx-html-content', prose, className)}
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: sanitize(children) }}
      />
    )
  }

  return (
    <div className={clsx('markdown-nyx', prose, className)}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          // Headings
          h1: ({ children }) => (
            <h1 className="text-nyx-moonbeam font-bold text-base mt-4 mb-2 first:mt-0">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-nyx-moonbeam font-semibold text-sm mt-4 mb-2 first:mt-0">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-nyx-moonbeam font-semibold text-xs uppercase tracking-wide mt-3 mb-1.5 first:mt-0">{children}</h3>
          ),

          // Paragraphs
          p: ({ children }) => (
            <p className="text-nyx-mist leading-relaxed mb-2 last:mb-0">{children}</p>
          ),

          // Lists
          ul: ({ children }) => (
            <ul className="text-nyx-mist space-y-1 mb-2 last:mb-0 pl-4 list-none">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="text-nyx-mist space-y-1 mb-2 last:mb-0 pl-4 list-decimal">{children}</ol>
          ),
          li: ({ children }) => (
            <li className="leading-relaxed flex gap-2 items-start">
              <span className="text-nyx-amethyst/70 mt-1.5 shrink-0 text-[8px]">◆</span>
              <span>{children}</span>
            </li>
          ),

          // Inline code
          code: ({ className: cls, children, ...props }) => {
            const match = /language-(\w+)/.exec(cls || '')
            const isBlock = !!match

            if (isBlock) {
              return (
                <SyntaxHighlighter
                  language={match![1]}
                  style={vscDarkPlus}
                  customStyle={{
                    margin: '8px 0',
                    borderRadius: '6px',
                    background: '#0d0d1a',
                    fontSize: '11px',
                    border: '1px solid rgba(99,79,161,0.2)',
                  }}
                  wrapLongLines
                >
                  {String(children).replace(/\n$/, '')}
                </SyntaxHighlighter>
              )
            }

            return (
              <code
                className="font-mono text-nyx-amethyst bg-nyx-eclipse/70 px-1 py-0.5 rounded text-[0.85em] border border-nyx-iris/20"
                {...props}
              >
                {children}
              </code>
            )
          },

          // Pre — handled by code component above for fenced blocks
          pre: ({ children }) => <>{children}</>,

          // Blockquote
          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-nyx-amethyst/40 pl-3 my-2 text-nyx-mist/70 italic">
              {children}
            </blockquote>
          ),

          // Strong / em
          strong: ({ children }) => (
            <strong className="text-nyx-moonbeam font-semibold">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="text-nyx-mist/80 italic">{children}</em>
          ),

          // Horizontal rule
          hr: () => <hr className="border-nyx-iris/20 my-3" />,

          // Links
          a: ({ href, children }) => (
            <a
              href={safeUrl(href ?? '')} // SEC-333: validate href scheme before rendering
              target="_blank"
              rel="noopener noreferrer"
              className="text-nyx-stardust hover:text-nyx-amethyst underline underline-offset-2 transition-colors"
            >
              {children}
            </a>
          ),

          // GFM tables
          table: ({ children }) => (
            <div className="overflow-x-auto my-2">
              <table className="w-full text-xs border-collapse">{children}</table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="border-b border-nyx-iris/20">{children}</thead>
          ),
          th: ({ children }) => (
            <th className="text-left text-nyx-mist/70 font-semibold uppercase tracking-wide text-[10px] px-3 py-2">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="text-nyx-mist px-3 py-2 border-b border-nyx-iris/10">{children}</td>
          ),

          // GFM strikethrough
          del: ({ children }) => (
            <del className="text-nyx-mist/40 line-through">{children}</del>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  )
}
