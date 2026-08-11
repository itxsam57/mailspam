import { resolve } from "node:path";
import { verifyRegressionVault } from "../../server/dist/devtools/regressionVault.js";

const results = await verifyRegressionVault(resolve(process.cwd(), "fixtures/regression-vault/v1"));
console.log(`Regression Vault passed: ${results.length} approved anonymized samples x 5 provider adapters.`);
