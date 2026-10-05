import { redirect } from "next/navigation";

import { TraceWorkspace } from "@/ui/workspace/TraceWorkspace";

export default async function TracePage({ searchParams }: { searchParams: Promise<{ url?: string | string[] }> }) {
  const raw = (await searchParams).url;
  const input = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  if (!input) redirect("/");
  // "example.com" means https://example.com, as in a browser's address bar.
  const url = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  return <TraceWorkspace url={url} />;
}
