# ERC-7984 explorer compatibility

PoD pTokens expose a narrow [EIP-7984](https://eips.ethereum.org/EIPS/eip-7984) surface so Blockscout and similar explorers can classify confidential tokens and index completed confidential transfers.

## Contracts

| File | Role |
|------|------|
| `IERC7984.sol` | Draft ERC-7984 interface (`bytes32` confidential pointers) |
| `IERC7984PortalWrapper.sol` | Partial wrapper events/views for `PrivacyPortal` |
| `Erc7984Constants.sol` | Interface id `0x4958f2a4` |
| `Erc7984Pointers.sol` | Maps PoD `ctUint256` to explorer handles |
| `PodErc7984Mixin.sol` | ERC-165 + metadata + `ConfidentialTransfer` emission |

`PodERC20` inherits `PodErc7984Mixin` and emits `ConfidentialTransfer` alongside the existing `Transfer` event when COTI callbacks succeed.

`PrivacyPortal` emits `WrapRequested` on deposit/wrap and `UnwrapRequested` / `UnwrapFinalized` on withdraw/release.

## Important notes

- This is **explorer compatibility**, not Zama FHE semantic equivalence.
- ERC-7984 transfer entry points revert with `Erc7984UsePodTransferMethods`; use native async `IPodERC20` methods for actual moves.
- Explorer-visible confidential transfers are emitted **only after async callback success** on production `PodERC20`.
- **Live Sepolia pMTT/pWETH/pUSDC deployments do not include this mixin yet** — they emit `Transfer` only until upgraded. Use `DummyTestPERC20` at fresh addresses for explorer testing without touching production contracts.

## Dummy test stack (no COTI)

| File | Role |
|------|------|
| `contracts/mocks/DummyTestPERC20.sol` | Synchronous test pToken with `ConfidentialTransfer` on every completed move |
| `contracts/mocks/PodCallbackTestInbox.sol` | Optional inbox stub to complete pending dummy mints/transfers |

Deploy and run on Sepolia (new addresses each run; saves `erc7984-dummy-deploy.json`):

```bash
npm run demo:erc7984-dummy-sepolia
```

Then verify the pToken on Blockscout Sepolia so `supportsInterface(0x4958f2a4)` and `ConfidentialTransfer` appear in the UI.

## Tests

```bash
npm run test:erc7984
```

Blockscout verification (requires deployed verified contracts):

```bash
ERC7984_EXPLORER_TESTS=1 \
ERC7984_PTOKEN=0x... \
ERC7984_BLOCKSCOUT_API=https://eth.blockscout.com/api/v2 \
npm run test:erc7984-explorer
```

Optional tx inspection:

```bash
npx tsx scripts/erc7984/check-blockscout.ts --token 0x... --tx 0x...
```
