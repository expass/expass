/** @type {import('npm-check-updates').RcOptions} */
module.exports = {
  target: (name) => name === '@types/node' ? 'minor' : 'latest',
};
