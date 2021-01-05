#!/usr/bin/env node

import yargs from 'yargs';
import Program from '../src/Program.js';

const program = new Program();
program.run(yargs(process.argv).argv);