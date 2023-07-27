require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.20",
  settings: {
    viaIR: true,
    optimizer: {
      enabled: true,
      details: {
        yulDetails: {
          optimizerSteps: "u",
        },
      },
    },
  },
};
