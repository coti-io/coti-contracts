import { extendProvider } from "hardhat/config";
import type { EIP1193Provider } from "hardhat/types";

/** Networks where RPC fee hints are multiplied by this factor (130% = +30%). */
const GAS_PRICE_MULTIPLIER_NUM = 130n;
const GAS_PRICE_MULTIPLIER_DEN = 100n;

const NETWORKS_WITH_BUMP = new Set(["coti-testnet", "coti-mainnet"]);

function bumpHexFee(value: unknown): unknown {
    if (typeof value !== "string" || !value.startsWith("0x")) {
        return value;
    }
    const v = BigInt(value);
    const bumped = (v * GAS_PRICE_MULTIPLIER_NUM) / GAS_PRICE_MULTIPLIER_DEN;
    return "0x" + bumped.toString(16);
}

function bumpBlockFeeFields(block: unknown): unknown {
    if (!block || typeof block !== "object") {
        return block;
    }
    const b = block as Record<string, unknown>;
    const out = { ...b };
    if (typeof b.baseFeePerGas === "string") {
        out.baseFeePerGas = bumpHexFee(b.baseFeePerGas);
    }
    return out;
}

extendProvider((provider: EIP1193Provider, _config, network: string) => {
    if (!NETWORKS_WITH_BUMP.has(network)) {
        return provider;
    }

    const originalRequest = provider.request.bind(provider);

    const wrapped: EIP1193Provider = Object.assign(
        Object.create(Object.getPrototypeOf(provider)),
        provider,
        {
            request: async (args: { method: string; params?: readonly unknown[] | object }) => {
                const result = await originalRequest(args);
                const method = args.method;

                if (method === "eth_gasPrice" || method === "eth_maxPriorityFeePerGas") {
                    return bumpHexFee(result);
                }

                if (method === "eth_getBlockByNumber" || method === "eth_getBlockByHash") {
                    return bumpBlockFeeFields(result);
                }

                return result;
            },
        }
    );

    return wrapped;
});
