module.exports = {
  // Instrument only the PoD surface we summarize in PIT CI. Skipping the MPC
  // mock zoo avoids multi-hour / hung instrumentation under viaIR.
  skipFiles: [
    "access/",
    "disperse/",
    "messaging/",
    "mocks/",
    "token/",
    "utils/mpc/MpcCore.sol",
    "pod/examples/",
  ],
  configureYulOptimizer: true,
};
