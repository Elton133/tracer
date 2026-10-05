import Link from "next/link";

const EXAMPLES = [
  { url: "https://example.com", note: "TLS 1.3, one round trip" },
  { url: "http://github.com", note: "redirect to https" },
  { url: "https://tls-v1-2.badssl.com:1012", note: "TLS 1.2, certificate in the clear" },
  { url: "https://expired.badssl.com", note: "an expired certificate" },
];

export default function Home() {
  return (
    <main className="flex flex-1 flex-col">
      <div className="px-6 pt-6 font-mono text-[13px] font-semibold tracking-[0.28em]">PACKET</div>

      <section className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center px-6 pb-24">
        <h1 className="text-[clamp(2.25rem,6vw,4.5rem)] leading-[0.95] font-semibold tracking-[-0.03em]">
          Where does your
          <br />
          request go?
        </h1>
        <p className="mt-5 max-w-xl text-[15px] leading-relaxed text-muted">
          Packet makes a real request from this machine and shows what happened: DNS, TCP, TLS, HTTP. Everything is
          labelled as either observed or derived, and Packet says so when it can&apos;t see something.
        </p>

        <form action="/trace" className="mt-10 flex flex-col gap-3 sm:flex-row">
          <input
            name="url"
            required
            autoFocus
            spellCheck={false}
            placeholder="https://example.com"
            aria-label="URL to trace"
            className="h-12 min-w-0 flex-1 rounded border border-line-strong bg-panel px-4 font-mono text-[15px] text-fg placeholder:text-faint focus:border-muted focus:outline-none"
          />
          <button className="h-12 rounded bg-fg px-6 font-mono text-[12px] font-semibold tracking-[0.16em] text-ink uppercase transition-opacity hover:opacity-90">
            Trace request
          </button>
        </form>

        <ul className="mt-8 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1">
          {EXAMPLES.map((ex) => (
            <li key={ex.url} className="contents">
              <Link href={`/trace?url=${encodeURIComponent(ex.url)}`} className="group col-span-2 grid grid-cols-subgrid items-baseline py-1">
                <span className="font-mono text-[12.5px] text-fg/85 group-hover:text-fg">{ex.url.replace(/^https?:\/\//, "")}</span>
                <span className="text-[12px] text-faint group-hover:text-muted">{ex.note}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
