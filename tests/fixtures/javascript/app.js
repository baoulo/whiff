/**
 * Harbour web app entry point.
 */
import express from 'express';
import { readFile } from 'node:fs/promises';
const path = require('path');

export class BoatStore {
  constructor() { this.boats = []; }
  add(b) { this.boats.push(b); }
}

export async function loadBoats(file) {
  const raw = await readFile(path.join(__dirname, file), 'utf8'); // "// not a comment"
  return JSON.parse(raw);
}

const greet = (name) => `Hello ${name}`;

const app = express();
app.get('/', (req, res) => res.send(greet('harbour')));
