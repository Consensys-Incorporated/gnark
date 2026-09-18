import { createPageUI, mustElement } from "./browser_utils.js";

export type BenchControls = { minLog: number; maxLog: number; iters: number };

/**
 * Wire the shared benchmark page chrome (min/max log2, iterations, Run
 * button, status, log) around `body`, which appends result lines and returns
 * the success message.
 */
export function installBenchPage(options: {
  title: string;
  idleMessage: string;
  autorun?: boolean;
  body: (lines: string[], writeLog: (lines: string[]) => void, controls: BenchControls) => Promise<string>;
}): void {
  const minLogEl = document.getElementById("min-log") as HTMLInputElement | null;
  const maxLogEl = document.getElementById("max-log") as HTMLInputElement | null;
  const itersEl = document.getElementById("iters") as HTMLInputElement | null;
  const runButton = document.getElementById("run") as HTMLButtonElement | null;
  const { setStatus, setPageState, writeLog } = createPageUI(document.getElementById("status"), document.getElementById("log"));

  async function run(): Promise<void> {
    const lines = [`=== ${options.title} ===`, ""];
    writeLog(lines);
    setStatus("Running");
    setPageState("running");
    mustElement(runButton, "run").disabled = true;
    try {
      const minLog = Number.parseInt(mustElement(minLogEl, "min-log").value, 10);
      const maxLog = Number.parseInt(mustElement(maxLogEl, "max-log").value, 10);
      const iters = Number.parseInt(mustElement(itersEl, "iters").value, 10);
      if (!Number.isInteger(minLog) || !Number.isInteger(maxLog) || !Number.isInteger(iters) || minLog < 1 || maxLog < minLog || iters < 1) {
        throw new Error("invalid benchmark controls");
      }
      const success = await options.body(lines, writeLog, { minLog, maxLog, iters });
      lines.push("", `PASS: ${success}`);
      writeLog(lines);
      setStatus("Pass");
      setPageState("pass");
    } catch (error) {
      lines.push(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
      writeLog(lines);
      setStatus("Fail");
      setPageState("fail");
    } finally {
      mustElement(runButton, "run").disabled = false;
    }
  }

  mustElement(runButton, "run").addEventListener("click", () => {
    void run();
  });
  if (options.autorun) {
    void run();
  } else {
    writeLog([`=== ${options.title} ===`, "", options.idleMessage]);
  }
}
