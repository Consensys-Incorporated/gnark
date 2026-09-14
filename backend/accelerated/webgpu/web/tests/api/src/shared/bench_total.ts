export async function benchmarkTotalDuration(
  iters: number,
  run: () => Promise<void>,
  yieldBetween?: () => Promise<void>,
): Promise<{ coldMs: number; warmMs: number }> {
  const measure = async (): Promise<number> => {
    const start = performance.now();
    await run();
    return performance.now() - start;
  };

  const coldMs = await measure();
  if (iters === 1) {
    return { coldMs, warmMs: coldMs };
  }

  let warmTotal = 0;
  for (let i = 0; i < iters; i += 1) {
    if (yieldBetween) {
      await yieldBetween();
    }
    warmTotal += await measure();
  }
  return { coldMs, warmMs: warmTotal / iters };
}
