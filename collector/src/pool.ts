// A bounded pool: runs `work` over the items with at most `limit` in flight, and returns each outcome at its item's
// index, so a caller that takes them in order gets the same order a serial loop would (cli.ts --concurrency, Prowler).

export async function pool<T, R>(items: readonly T[], limit: number, work: (item: T, index: number) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
  const out: PromiseSettledResult<R>[] = new Array(items.length);
  let next = 0;
  const lane = async () => {
    for (let i = next++; i < items.length; i = next++) {
      try { out[i] = { status: "fulfilled", value: await work(items[i], i) }; } catch (reason) { out[i] = { status: "rejected", reason }; }
    }
  };
  const n = Math.max(1, Math.min(Math.floor(limit) || 1, items.length));
  await Promise.all(Array.from({ length: n }, lane));
  return out;
}
