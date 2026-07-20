# PrivacyPortal + pERC20 — Internal Security Review

**Scope:** `coti-contracts/contracts/pod/` — `privacy/PrivacyPortal.sol`, `privacy/PrivacyPortalFactory.sol`, `privacy/PrivacyPortalFeeLib.sol`, `privacy/PortalFeeOracle.sol`, `token/perc20/PodERC20.sol`, `token/perc20/PodErc20Mintable*.sol`, `token/perc20/cotiside/PodErc20CotiMother.sol`, `token/erc7984/PodErc7984Mixin.sol`, and the inbox-user wiring. The inbox/miner layer is reviewed separately in `coti-pod-inbox-contracts/audit/POD_INBOX_AUDIT.md`; here it is treated as an external trust boundary.

**Method:** full manual read of the in-scope contracts, tracing deposit (lock → async mint → callback) and withdrawal (permit → transfer-to-portal → release → batch burn) end-to-end, including the cross-repo inbox↔pToken↔mother interaction. Read-and-report; no contract code was modified. Branch `naiem/parity` at `5f3cf7f`; the tree compiles.

---

## 1. Architecture & value flow

```
 Source chain (Sepolia / Fuji)                              COTI chain
 ┌───────────────────────────────────────┐            ┌────────────────────────────┐
 │ user ── deposit(amount) ─▶ PrivacyPortal            │  PodErc20CotiMother         │
 │            │ lock ERC20 collateral     │            │  (unified garbled ledger)   │
 │            │ pToken.mint{mintFee} ─────┼── inbox ───┼─▶ mint → respond(callback)  │
 │            ▼                           │            │        │                    │
 │       PodERC20 (pToken) ◀─────────────┼── inbox ───┼── transferCallback (Success)│
 │            ▲ transferFromAndCall…      │            │        balances (ctUint256) │
 │ user ─ requestWithdrawWithPermit ──────┼── inbox ───┼─▶ transferFromPublic        │
 │            │ onPTokenTransferred       │            │                             │
 │            ▼ release ERC20 collateral  │            │                             │
 └───────────────────────────────────────┘            └────────────────────────────┘
```

**Solvency model.** Underlying ERC20 is locked in the portal 1:1 before an async pToken mint. Withdrawals pull the pToken into portal custody (`transferFromAndCallWithPermit`), release the underlying on transfer `Success`, and accumulate the pToken in `pendingBurnAmount` for a later admin batch burn. Between release and burn, *total* pToken supply temporarily exceeds locked underlying by `pendingBurnAmount`; the invariant holds because the portal never withdraws against its own custody (circulating supply excluding portal custody stays matched to locked collateral).

**Trust boundary.** Every mint/release/failure decision is driven by an inbox callback whose authenticity ultimately rests on the miner (inbox POD-01). Findings marked "cross-product" are where portal safety depends on that assumption. The pToken authenticates callbacks with `onlyInbox` + a peer match against `(cotiChainId, cotiSideContract)`, and applies a monotonic per-account `balanceNonces` guard so stale callbacks cannot overwrite newer balances — correct given an honest inbox.

**Governance.** Portals have no local `Ownable`; admin/operator powers live on the factory via OpenZeppelin `AccessControl` (`DEFAULT_ADMIN_ROLE`, `OPERATOR_ROLE`). The factory owns each pToken clone so it can rotate routing after inbox/mother upgrades.

---

## 2. Findings

| ID | Title | Severity |
|----|-------|----------|
| PP-01 | Forged inbox callback (trusted-miner edge) releases collateral without a burn / mints without a lock | Critical (cross-product, by design) |
| PP-02 | Deposits stuck `Pending` are permanently non-refundable if the callback never arrives | High |
| PP-03 | Failed one-way token registration bricks all deposits to a portal | High |
| PP-04 | `MpcCore.decrypt(ge(...))` leaks a solvency bit → adaptive balance probing on encrypted transfers | High (privacy) |
| PP-05 | Zero-value `transferFromAndCall` is an allowance-free authenticated callback primitive | High (integration-dependent) |
| PP-06 | Fee-on-transfer / rebasing underlying breaks 1:1 collateralization | Medium |
| PP-07 | Failed asynchronous batch burn permanently loses `pendingBurnAmount` accounting | Medium |
| PP-08 | Third-party deposits / `transferFrom` lock the recipient's / owner's single pending slot (griefing DoS) | Medium |
| PP-09 | Admin can move user collateral via `rescueERC20` while paused | Medium (by design) |
| PP-10 | Blacklist checks only `msg.sender`; listed recipients remain reachable | Medium (policy-dependent) |
| PP-11 | Unilateral pToken inbox/peer and routing rotation, no timelock | Low |
| PP-12 | Self-transfers leave the PoD-side ciphertext cache understated | Low |
| PP-13 | Caller-supplied token decimals can misprice fees or brick dynamic-fee paths | Low |
| PP-14 | Deposit escrow never reaches a terminal success state | Low |
| PP-15 | Direct native sends inflate balance outside fee accounting | Informational |

---

### PP-01 — Forged callback releases collateral without a real burn (Critical, cross-product / by design)

Withdrawal release is gated solely on the pToken transfer request being `Success`:

```703:710:contracts/pod/privacy/PrivacyPortal.sol
        IPodERC20.RequestStatus requestStatus = pToken.requests(withdrawal.transferRequestId).status;
        if (requestStatus != IPodERC20.RequestStatus.Success) {
            revert PTokenTransferNotSuccessful(withdrawal.transferRequestId, requestStatus);
        }
        withdrawal.status = WithdrawalStatus.Released;
        underlyingToken.safeTransfer(withdrawal.recipient, withdrawal.amount);
```

That `Success` is written by `PodERC20.transferCallback`, whose only authentication is `onlyInbox` + a peer match:

```302:307:contracts/pod/token/perc20/PodERC20.sol
    function transferCallback(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
```

Both `inboxMsgSender()` values originate from miner-supplied `incomingRequests[...].originalSender` (inbox POD-01). A malicious miner can deliver a forged `transferCallback` marking a withdrawal `Success` with no pToken actually burned on COTI; `triggerWithdrawalRelease` (permissionless) then pays out the underlying, leaving the portal undercollateralized. The mirror image lets a miner forge a `mint` on the mother ledger and credit private balances with no locked collateral. The portal's authentication is correct *given a trustworthy inbox* — this is the concrete portal-side impact of the trusted-miner model and should headline the joint threat model.

**Mitigations** live at the inbox layer (M-of-N attestation / receipt proofs; inbox POD-01). Portal-side defense-in-depth: a per-portal withdrawal rate-limit / timelock so a single forged batch cannot drain the whole reserve instantly.

---

### PP-02 — Deposits stuck `Pending` are permanently non-refundable (High)

`refundFailedDeposit` only refunds when the mint request is `SystemFailed`:

```505:510:contracts/pod/privacy/PrivacyPortal.sol
        IPodERC20.RequestStatus mintStatus = pToken.requests(requestId).status;
        // Mint should not `raise`; only Inbox system errors are refundable.
        // Permissionless: anyone may trigger; underlying always returns to {escrow.user}.
        if (mintStatus != IPodERC20.RequestStatus.SystemFailed) {
            revert DepositMintNotFailed(requestId, mintStatus);
```

If the mint callback never arrives (for example, because the miner censors/stalls), the pToken request stays `Pending`. An inbox execution revert also intentionally leaves it `Pending` because `revert` is retryable (inbox POD-03); a later `retryFailedRequest` can complete a transient failure such as insufficient execution gas. If retries can never succeed, however, there is no terminal cancellation or admin-forced refund, and the only escape is the catastrophe `rescueERC20` (which pays the rescue recipient, not the depositor).

**Recommendation:** add a recovery escape for long-`Pending` escrows — but a naive elapsed-time refund is unsafe, because a late COTI mint could execute after the refund and create unbacked pTokens. Recovery needs a COTI-acknowledged cancellation/finality signal (or a provably terminal failure), not elapsed time alone.

---

### PP-03 — Failed registration bricks all deposits to a portal (High)

`createPortal` registers the pToken namespace on the mother via a one-way, error-handler-less inbox message:

```487:490:contracts/pod/privacy/PrivacyPortalFactory.sol
        requestId = IInbox(inbox).sendOneWayMessage{value: msg.value}(
            cotiChainId, cotiMotherContract, methodCall, bytes4(0)
        );
```

Insufficient `msg.value` reverts `createPortal` atomically (both clones roll back), so the failure modes are post-submission remote execution failure or censorship. If registration does not land, the mother's `onlyRegisteredPTokenMessage` gate rejects every subsequent mint/transfer (`TokenNotRegistered`). Those execution reverts intentionally remain retryable and leave each deposit's mint `Pending` (inbox POD-03), compounding PP-02. Recovery exists but is manual: once registration succeeds, permissionless `retryFailedRequest(mintRequestId)` can re-drive each failed mint.

**Recommendation:** make registration a two-way message with an error handler, and block deposits behind a `registered` flag flipped by a registration confirmation (or a portal-level "not yet live" guard).

**Implementation note (docs-only fix landed):** `createPortal` now carries explicit NatSpec stating that it returns as soon as the mother-registration message is *submitted*, not once it is confirmed, and instructs the deployer to keep (or immediately set) the new portal's `isDepositEnabled` to `false` until registration is externally confirmed — i.e. **no portal activity (deposits) until mother registration is confirmed; enable deposits only after registration.** This is a process control using the existing soft-deposit switch, not a new on-chain `registered` flag; the two-way-message/registered-flag hardening above remains open.

---

### PP-04 — `decrypt(ge(...))` leaks a solvency bit; enables balance probing (High, privacy)

The mother decrypts a garbled comparison in cleartext for every move:

```385:389:contracts/pod/token/perc20/cotiside/PodErc20CotiMother.sol
        if (!MpcCore.decrypt(MpcCore.ge(senderBalance, amount))) {
            _sendTransferFailureToPod(id, from, to, bytes("PodErc20CotiMother: insufficient balance"));
            return;
        }
```

`MpcCore.decrypt` publishes the plaintext boolean `balance >= amount` on-chain, and the failure branch `raise`s a cleartext `"insufficient balance"` reason (same for `"insufficient allowance"`). For plain-amount flows the amount is already public, so this leaks little. But for **encrypted** (`itUint256`) transfers — the privacy-sensitive path the product exists to protect — an observer learns, for a chosen encrypted amount, whether the sender's balance is above or below it. A party able to induce authorized moves (the account owner, an approved spender, or anyone who can trigger the victim's transfers) can binary-search the exact balance across a sequence of transfers. A completely unaffiliated observer cannot probe arbitrary victims, which bounds the finding — but it materially weakens the confidentiality guarantee.

**Recommendation:** branch on a garbled/`mux` result instead of a decrypted boolean (clamp to `min(balance, amount)` or no-op via MPC without revealing the comparison); at minimum make failure reasons uniform so the leak is not amplified by distinct messages. Document whichever path is chosen as a confidentiality limitation.

---

### PP-05 — Zero-value authenticated callback primitive (High, integration-dependent)

`transferFromAndCall` accepts zero amount and arbitrary callback bytes, and neither the PoD side nor the mother rejects zero:

```184:201:contracts/pod/token/perc20/PodERC20.sol
    function transferFromAndCall(
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId) {
        requestId = _transferPublicFrom(
            IPodErc20CotiSide.transferFromPublicAsSpender.selector,
            msg.sender, from, to, amount, msg.value, callbackFeeLocalWei
        );
        _requestCallbacks[requestId] = data;
    }
```

On COTI, both `balance >= 0` and `allowance >= 0` succeed even for an attacker with no allowance, so the success `transferCallback` then executes arbitrary `data` via `to.call(callbackData)` with `msg.sender == pToken`. Any caller can therefore (1) make an arbitrary call *from the trusted pToken address* without transferring value, and (2) occupy a victim's pending-transfer slot until the round trip settles (see PP-08). No direct portal drain was found because `_releaseWithdrawal` independently rechecks the recorded withdrawal's status; the risk is to any integration that treats `msg.sender == pToken` (or a fired callback) as proof of a positive transfer.

**Recommendation:** reject zero public transfer/`transferFrom` amounts on both chains; replace raw callbacks with a standardized hook carrying verifiable `requestId`, `from`, and `amount` that receivers must validate.

---

### PP-06 — Fee-on-transfer / rebasing underlying breaks collateralization (Medium)

Deposits mint exactly `amount` pToken against a `safeTransferFrom` of `amount`, with no measured-received check:

```342:344:contracts/pod/privacy/PrivacyPortal.sol
        underlyingToken.safeTransferFrom(msg.sender, address(this), amount);
        requestId = pToken.mint{value: mintFee}(recipient, amount, mintCallbackFee);
```

For a fee-on-transfer token the portal receives less than `amount` but mints `amount` pToken → structurally undercollateralized; rebasing tokens break the invariant over time.

**Recommendation:** measure `balanceOf(this)` before/after and mint the delta, or restrict `createPortal` to vetted standard-ERC20 underlyings and document the exclusion.

---

### PP-07 — Failed batch burn loses accounting (Medium)

`burnAccumulatedPTokens` decrements `pendingBurnAmount` *before* the async burn is known to have succeeded, and stores no `burnRequestId => amount` reconciliation record:

```562:565:contracts/pod/privacy/PrivacyPortal.sol
        pendingBurnAmount -= amount;
        burnRequestId = pToken.burn{value: msg.value}(amount, burnCallbackFee);
        emit BatchBurnSubmitted(msg.sender, amount, burnRequestId);
```

If the burn becomes `Failed`/`SystemFailed`, its tokens remain in portal custody but are no longer counted by `pendingBurnAmount`, and the counter cannot be restored (the paired pToken cannot be rescued — `rescueERC20` reverts on the pToken). A burn stuck `Pending` also holds the portal's single pToken sender lock and blocks all later burns.

**Recommendation:** track each batch burn as `Pending/Succeeded/Failed`; decrement finalized accounting only on success, or permissionlessly restore the amount after a terminal failure.

---

### PP-08 — Pending-slot griefing on recipients and owners (Medium)

The pToken uses a single `_pendingTransferRequestIds[account]` slot. Both incoming mints and outgoing transfers/burns contend for it, keyed on the affected account:

```995:1012:contracts/pod/token/perc20/PodERC20.sol
    function _mintPublic(address to, uint256 amount, ...) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(address(0), to, _pendingTransferRequestIds[to]);
        }
        ...
        _lockTransferPending(requestId, to, true);
```

Anyone can choose a deposit recipient, so an attacker can make minimum-size deposits to a victim and block that victim's outgoing pToken operations during each async mint; callback loss/censorship makes the lock indefinite. Symmetrically, `transferFrom` variants lock `from`'s slot and are callable by anyone (the allowance is only checked later on COTI, and per PP-05 zero amounts pass), so an attacker with no allowance can keep a victim's `from` slot occupied.

**Recommendation:** do not let incoming mints occupy the recipient's outgoing-transfer lock (track pending mints separately and rely on nonce-ordered reconciliation); key the transfer lock on the request initiator or `(from, spender)`, or let the owner cancel a spender-induced lock.

---

### PP-09 — Admin can move user collateral via rescue while paused (Medium, by design)

```611:623:contracts/pod/privacy/PrivacyPortal.sol
    function rescueERC20(address token, uint256 amount) external onlyFactoryAdmin nonReentrant whenPaused {
        ...
        if (token == address(pToken)) {
            revert CannotRescuePToken();
        }
        ...
        IERC20(token).safeTransfer(recipient, amount);
```

`rescueERC20`/`rescueNative` can transfer the underlying collateral (only the paired pToken is excluded) to the factory `rescueRecipient` whenever a factory admin pauses. This is a deliberate catastrophe hatch (gated on `whenPaused`, fixed destination), but it is unbounded custodial power: a compromised/malicious admin can seize all user deposits after a pause.

**Recommendation:** route rescue through a timelock/multisig, cap or event-announce rescues, and document the trust placed in the factory admin.

---

### PP-10 — Blacklisted recipients remain reachable (Medium, policy-dependent)

`_checkNotBlacklisted` checks only `msg.sender`; deposit and withdrawal recipients are arbitrary and unchecked:

```848:852:contracts/pod/privacy/PrivacyPortal.sol
    function _checkNotBlacklisted() private view {
        if (blacklisted[msg.sender] || _factory().blacklisted(msg.sender)) {
            revert AddressBlacklisted(msg.sender);
        }
    }
```

An unlisted caller can mint pTokens to, or withdraw underlying directly to, a blacklisted recipient. If the policy is only to block listed *callers* from initiating, this is by design; if it must prevent listed accounts from *receiving* bridged assets, it is bypassable.

**Recommendation:** define the compliance semantics explicitly; if receipt must be blocked, check both initiator and recipient at both portal and factory layers, while preserving safe refund/recovery for accounts blacklisted after submission.

---

### PP-11 — Unilateral routing rotation, no timelock (Low)

`PodERC20.configure` (owner), `PrivacyPortalFactory.configurePToken` / `configureRouting` / `transferPTokenOwnership` (admin), and `PodErc20CotiMother.configure` (owner) can repoint a live pToken's `inbox`/`cotiSideContract` or the mother's inbox at any time, with no timelock or two-step. A wrong or malicious rotation redirects/authenticates callbacks against a new peer and can brick or hijack in-flight requests. Events exist; timelock does not.

**Recommendation:** timelock these rotations and keep the prominent events.

---

### PP-12 — Self-transfer corrupts the local balance cache (Low)

On COTI a self-transfer (`from == to`) computes `senderAfter`, then reads that reduced balance as `recipientBefore` and adds the amount back, restoring the authoritative balance. On PoD, `transferCallback` applies the sender update first, then skips the recipient update because `to == from` and `balanceNonces[to]` already equals the callback nonce:

```319:330:contracts/pod/token/perc20/PodERC20.sol
        if (from != address(0)) {
            if (balanceNonces[from] < nonce) {
                _balances[from] = newBalanceFrom;
                balanceNonces[from] = nonce;
            }
        }
        if (to != address(0)) {
            if (balanceNonces[to] < nonce) {
                _balances[to] = newBalanceTo;
```

The COTI ledger stays correct, but the PoD ciphertext cache shows `oldBalance - amount` until a later update or sync.

**Recommendation:** reject self-transfers or special-case them so the recipient balance is applied once.

---

### PP-13 — Unvalidated decimals can disable dynamic fee paths (Low)

`createPortal` accepts a caller-supplied `uint8 decimals` and propagates it to the portal and pToken without comparing to the underlying. Dynamic pricing computes `10 ** decimals` (`PrivacyPortalFeeLib.resolvePortalFee`): a wrong value misprices percentage fees, and a value above ~77 overflows and reverts estimates, deposits, and withdrawals whenever dynamic pricing is reached. Only allowlisted deployers can cause this, so it is a deployment-integrity issue, not a public exploit.

**Recommendation:** read `IERC20Metadata(underlying).decimals()`, compare with the requested value, and bound supported decimals.

---

### PP-14 — Deposit escrow has no terminal success state (Low)

`depositEscrows[requestId]` is written `Pending` and only ever transitions to `Refunded`; on mint success nothing marks it consumed. This is functionally fine (collateral legitimately stays locked backing minted supply) but "Pending" conflates "in-flight" with "successfully backing supply," complicating monitoring and any PP-02 recovery design.

**Recommendation:** add a `Completed` status set from the mint success callback so recovery can distinguish never-resolved from resolved deposits.

**Resolution:** Declined. A permissionless `finalizeDepositEscrow` bookkeeping path would not be used in practice; successful mints are observed via pToken request status. Stuck `Pending` recovery remains {adminRefundPendingDeposit} (PP-02).

---

### PP-15 — Direct native sends inflate balance outside accounting (Informational)

`receive()` accepts arbitrary native but only `accumulatedPortalFees` is tracked; directly-sent native is recoverable only via `rescueNative` (while paused). `withdrawPortalFees` caps at `accumulatedPortalFees`, so this cannot over-sweep fees. Noted for completeness.

---

## 3. Items checked and found sound

- **EIP-712 `TransferPermit`** (`_consumePublicTransferPermit`): domain separator binds `name`, version `"1"`, `block.chainid`, and `address(this)`; per-owner nonce increments; deadline enforced; the portal passes `from = msg.sender` and the permit recovers `signer == from`, so a third party cannot replay someone else's permit. Distinct pToken addresses → distinct domains, so no cross-portal/cross-chain reuse.
- **Withdrawal double-release / state machine:** `_releaseWithdrawal` transitions `TransferPending → Released` before transferring; `onPTokenTransferred` and `triggerWithdrawalRelease` both funnel through it and re-check status, so no double release. `cancelFailedWithdrawal` requires `Failed`/`SystemFailed` and moves no funds.
- **Reentrancy:** all external mutators are `nonReentrant`; `PodERC20._sendPodTwoWay` is `nonReentrant`, so a hostile inbox/oracle cannot re-enter before pending locks are written. `transferCallback`'s `to.call(callbackData)` runs after state is committed; a failed hook only emits `RequestCallbackFailed` and leaves the withdrawal recoverable via the permissionless trigger.
- **Clone init ordering:** implementations call `_disableInitializers()`; `createPortal` clones and `initialize`s both portal and pToken atomically in one tx → no front-run window.
- **`tokenId` namespacing:** `sourceChainId(uint64) << 160 | pToken(uint160)` with an explicit `ChainIdOverflow` guard → no collisions across chains/tokens.
- **Fee math (`PrivacyPortalFeeLib`):** packing bounds-checks field widths and rejects `maxFee == 0`, `fixedFee > maxFee`, `bps > 10%`; `resolvePortalFee` falls back to fixed fee when a rate or `bps` is zero (safe default). Floor/cap enforced in `_validateAndCollectPortalFee`.
- **Callback nonce staleness:** `balanceNonces[account] < nonce` guard with mother-side nonces starting at `INITIAL_TOKEN_NONCE = 1` (PoD defaults 0) ensures the first callback applies and stale replays are ignored.
- **App-level `Failed` refundability:** only `SystemFailed` is refundable; an app `raise` (`Failed`) is non-refundable by interface contract. Today the mint path only `raise`s on `to == address(0)`, which the portal already rejects, so mints should not reach `Failed`. Residual risk is a future mother-side change adding an app-`raise` on the mint path — keep an invariant/test asserting the mint path never `raise`s.
- **Migrated error handling:** `PodERC20` error callbacks use `_errorCallbackContext()` (`onlyInbox` + `inboxErrorType()` + non-zero, `Pending` `sourceRequestId`) and branch `SystemError` vs `Exception` — correctly consuming the new `SYSTEM_SENDER` path (inbox POD-12) rather than requiring peer equality.

---

## 4. By-design trade-offs

| Trade-off | Risk carried | Safer alternative |
|-----------|--------------|-------------------|
| **Callback authenticity rests on the miner** (PP-01) | Forged callback → release without burn / mint without lock → insolvency | Inbox M-of-N or receipt proofs; portal-side withdrawal rate-limit/timelock |
| **Only `SystemFailed` is refundable; `Pending`/`Failed` are not** (PP-02) | Censored / dropped deposits lock user funds | COTI-acknowledged cancellation/finality for stuck deposits (not elapsed time) |
| **Public deposit/withdraw amounts** | Amounts visible in calldata/events at the portal boundary | Inherent to a public bridge boundary; documented |
| **`decrypt(ge(...))` balance check** (PP-04) | 1-bit solvency leak → adaptive balance probing on encrypted flows | MPC-select/clamp without decrypting the comparison |
| **Admin rescue of collateral while paused** (PP-09) | Custodial seizure of user funds | Timelock + cap + announced rescue |
| **Standard-ERC20 assumption** (PP-06) | FoT/rebasing underlyings break 1:1 backing | Measured-received minting or an underlying allowlist |

---

## 5. Checklist

| Category | Result | Notes |
|----------|--------|-------|
| Reentrancy (single/cross-fn/cross-contract) | Pass | All mutators `nonReentrant`; callbacks commit state before external `call`; `_sendPodTwoWay` guarded |
| Read-only reentrancy | Pass | Release gated on stored status, not a live private read |
| Access control / modifiers | Pass | `onlyFactoryAdmin/Operator`, `onlyPToken`, `onlyInbox`, `onlyRegistered*Message`, minter check |
| Unprotected initializer / clone ordering | Pass | `_disableInitializers` + atomic factory clone-and-init |
| `tx.origin` auth | Pass | Not used |
| Integer overflow/underflow | Warn | 0.8 checked math; fee packing width-checked; unvalidated `decimals` can overflow `10**decimals` (PP-13) |
| Unchecked casts / bit truncation | Pass | `tokenId`/fee packs bounds-checked; `uint64(amount)` in an event only |
| Rounding / precision loss | Pass | `Math.mulDiv` in fee/USD conversion; fixed-fee fallback |
| Unchecked external call returns | Pass | `safeTransfer*`; native sends `require`/revert-checked; hook failure captured |
| Gas forwarding / callback stall | Warn | `transferCallback` hook uses all remaining gas; failure recoverable via trigger |
| Availability / liveness | Fail | Stuck `Pending` deposits (PP-02); registration brick (PP-03); pending-lock griefing (PP-08) |
| Tx ordering / MEV | Pass | Permit bound to owner+nonce+deadline; release idempotent |
| Signature / permit reuse | Pass | Per-owner nonce, deadline, domain-bound to token+chain |
| Missing deadline | Pass | Permit deadline enforced |
| Oracle robustness | Pass | Zero/`bps==0` rate → fixed-fee fallback; `PortalFeeOracle` is admin-set (documented trust) |
| `delegatecall` / selfdestruct | Pass | None used |
| Unexpected ETH / `msg.value` accounting | Warn | Untracked direct sends (PP-15); cannot over-sweep fees |
| Centralization / timelock | Warn | Admin rescue (PP-09) and routing rotation (PP-11) lack timelock |
| Event / accounting integrity | Warn | Lifecycle events on every transition; batch-burn accounting lost on async failure (PP-07) |
| Storage-gap upgrade safety | N/A | Minimal-proxy clones are non-upgradeable, fixed implementation |
| Pragma / opcodes | Pass | `^0.8.20`, Paris-compatible (storage ReentrancyGuard, plain AccessControl) |
| **Collateral solvency invariant** | **Warn/Fail** | Holds for standard ERC20 with an honest inbox; broken by PP-01 (forged callback), PP-06 (FoT), PP-07 (lost burn accounting) |
| Mint-before-lock ordering | Pass | Collateral locked before mint request in all deposit paths |
| Escrow state-machine holes | Warn | No terminal success state (PP-14); non-refundable `Pending`/`Failed` classes (PP-02) |
| Double-release / refundable classes | Pass | Status-guarded single release; refund/cancel gated correctly |
| pToken callback auth + stale nonce | Pass* | Correct given an honest inbox; *forgeable by miner (PP-01) |
| Authenticated-callback / zero-value abuse | Fail | Zero-value `transferFromAndCall` yields an allowance-free pToken-authenticated call (PP-05) |
| MPC information disclosure | Fail | `decrypt(ge())` balance-probe leak on encrypted flows (PP-04) |
| `tokenId` namespace collision | Pass | Width-checked pack |
| First-depositor / donation / FoT | Warn | FoT/rebasing unhandled (PP-06); no share-based accounting so donation is inert |
| Blacklist / compliance semantics | Warn | Only `msg.sender` checked; recipients reachable (PP-10) |

**Legend:** Pass = no issue found; Warn = works but carries a documented risk; Fail = action required; N/A = not applicable.

---

## 6. Priority actions before launch

1. **PP-01** — mitigate at the inbox layer (M-of-N attestation / proofs) and add a portal-side withdrawal rate-limit/timelock as defense-in-depth.
2. **PP-05** — reject zero-value public transfers and harden the callback into a verifiable standardized hook.
3. **PP-02 / PP-03** — implement a COTI-acknowledged cancellation/finality path for stuck deposits and make token registration confirmed (two-way) before deposits are accepted.
4. **PP-04** — remove or reduce the `decrypt(ge())` balance leak on encrypted flows, or document it as a hard confidentiality limitation.
5. **PP-07 / PP-08** — add async batch-burn reconciliation; decouple incoming-mint locks from a recipient's outgoing-transfer slot.
6. **PP-06 / PP-13** — measured-received minting or a vetted-underlying allowlist; validate `decimals` at creation.
7. **PP-09 / PP-11** — timelock/multisig the rescue and routing-rotation powers.
