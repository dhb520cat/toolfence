#!/usr/bin/env node
"use strict";
// MCP stdio 传输:一行一个 JSON-RPC 消息,stdio 直通。
require("./_python").run("toolfence.server", process.argv.slice(2));
