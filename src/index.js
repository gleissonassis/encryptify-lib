import yargs from 'yargs';
import Program from './Program.js';

const program = new Program();
program.run(yargs(process.argv).argv);