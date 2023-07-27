require("@nomicfoundation/hardhat-toolbox");
require('hardhat-abi-exporter');

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
  abiExporter: [
    {
      path: './abi/',
      format: "json",
      only: ['Frens'],
    }
  ]
};

