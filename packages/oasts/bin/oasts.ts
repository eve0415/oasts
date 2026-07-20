#!/usr/bin/env node
import { run } from "../src/cli.ts";

process.exit(await run(process.argv.slice(2), process.cwd(), process.stdout, process.stderr));
