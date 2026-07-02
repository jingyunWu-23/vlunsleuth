const fs = require("fs");

function readStdin() {
  return fs.readFileSync(0, "utf8");
}

function pickCompiler(input) {
  const contents = Object.values(input.sources || {})
    .map((source) => String(source.content || ""))
    .join("\n");
  const match = contents.match(/pragma\s+solidity\s+([^;]+);/);
  const pragma = match ? match[1] : "";
  if (/\b0\.4\.25\b/.test(pragma) && !/[\^~><=]/.test(pragma.replace("0.4.25", ""))) {
    return { name: "solc-0-4-25", solc: require("solc-0-4-25") };
  }
  if (/0\.4\.|[\^>=<~ ]4\./.test(pragma)) {
    return { name: "solc-0-4", solc: require("solc-0-4") };
  }
  if (/0\.8\.|[\^>=<~ ]8\./.test(pragma)) {
    return { name: "solc-0-8", solc: require("solc-0-8") };
  }
  try {
    return { name: "solc-0-8", solc: require("solc-0-8") };
  } catch (error) {
    return { name: "solc", solc: require("solc") };
  }
}

function compileStandard(solc, inputText) {
  if (typeof solc.compileStandardWrapper === "function") {
    return solc.compileStandardWrapper(inputText);
  }
  const output = solc.compile(inputText);
  return typeof output === "string" ? output : JSON.stringify(output);
}

const inputText = readStdin();
const input = JSON.parse(inputText);
const selected = pickCompiler(input);
const outputText = compileStandard(selected.solc, inputText);
process.stdout.write(outputText);
