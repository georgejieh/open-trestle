import React, { useState as useLocal, useEffect } from "react";
import * as path from "node:path";
const fs = require("fs");
export const LIMIT = 3;
let counter = 0;

export default class Widget extends React.Component {
  #secret = 1;
  constructor(props) { super(props); this.state = {}; }
  render() { return <Panel.Body title={path.join("a", "b")} />; }
}

export function helper(a) {
  const inner = () => fs.readFileSync(a);
  return inner();
}

const handlers = { onClick: () => helper(1) };
export { handlers };
