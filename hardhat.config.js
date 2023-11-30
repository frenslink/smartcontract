require("@nomicfoundation/hardhat-toolbox");
require('hardhat-abi-exporter');

module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      "viaIR": true,
    }
  },
  contractSizer: {
    alphaSort: true,
    disambiguatePaths: false,
    runOnCompile: true,
    strict: true,
    only: [':ERC20$'],
  },
  abiExporter: [
    {
      path: './abi/',
      format: "json",
      flat: true,
      only: ['Frens'],
    }
  ]
};

