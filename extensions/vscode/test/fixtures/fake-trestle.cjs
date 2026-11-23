// A stand-in for trestle. The first argument picks what it does.
const [mode, ...args] = process.argv.slice(2);
if (mode === "report") {
  process.stdout.write(
    JSON.stringify({ args, environment: Object.keys(process.env) }),
  );
} else if (mode === "stderr") {
  process.stderr.write("first line\r\nsecond ");
  setTimeout(() => process.stderr.write("line\nlast line"), 50);
} else if (mode === "flood") {
  // Ignores its input and writes until it is killed.
  process.stdin.resume();
  const block = "x".repeat(64 * 1024);
  const write = () => {
    while (process.stdout.write(block));
    process.stdout.once("drain", write);
  };
  write();
} else if (mode === "wait") {
  process.stderr.write("running\n");
  process.stdin.resume();
  process.stdin.on("end", () => {
    process.stderr.write("stopped\n");
    process.stdout.write('{"version":"2.1.0","runs":[]}');
    process.exitCode = 3;
  });
}
