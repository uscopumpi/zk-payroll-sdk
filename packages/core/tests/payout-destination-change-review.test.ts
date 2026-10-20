import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { reviewPayoutDestinationChange } from "../src/employees";

const CURRENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11)).publicKey();
const PROPOSED = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 12)).publicKey();

describe("reviewPayoutDestinationChange", () => {
  it("builds a masked, standard-risk review for a valid account change", () => {
    const result = reviewPayoutDestinationChange({
      currentDestination: CURRENT,
      proposedDestination: PROPOSED,
    });

    expect(result).toEqual({
      ok: true,
      review: {
        current: { preview: `${CURRENT.slice(0, 6)}…${CURRENT.slice(-4)}`, kind: "account" },
        proposed: {
          preview: `${PROPOSED.slice(0, 6)}…${PROPOSED.slice(-4)}`,
          kind: "account",
        },
        risk: "standard",
        warnings: [],
      },
    });
    expect(JSON.stringify(result)).not.toContain(CURRENT);
    expect(JSON.stringify(result)).not.toContain(PROPOSED);
  });

  it("rejects an unchanged destination", () => {
    expect(
      reviewPayoutDestinationChange({
        currentDestination: CURRENT,
        proposedDestination: CURRENT,
      })
    ).toMatchObject({ ok: false, code: "DESTINATION_UNCHANGED" });
  });

  it("reports which side is invalid without echoing submitted values", () => {
    const privateValue = "invalid-private-destination";
    const invalidCurrent = reviewPayoutDestinationChange({
      currentDestination: privateValue,
      proposedDestination: PROPOSED,
    });
    const invalidProposed = reviewPayoutDestinationChange({
      currentDestination: CURRENT,
      proposedDestination: privateValue,
    });

    expect(invalidCurrent).toMatchObject({
      ok: false,
      code: "CURRENT_DESTINATION_INVALID",
      validationCode: "DESTINATION_UNSUPPORTED",
    });
    expect(invalidProposed).toMatchObject({
      ok: false,
      code: "PROPOSED_DESTINATION_INVALID",
      validationCode: "DESTINATION_UNSUPPORTED",
    });
    expect(JSON.stringify([invalidCurrent, invalidProposed])).not.toContain(privateValue);
  });

  it("flags an account-type change for elevated review", () => {
    // Built with `Uint8Array`/`DataView` rather than `Buffer` so the test runs
    // unchanged in the browser (jsdom) environment as well as in Node.
    const muxedPayload = new Uint8Array(40);
    muxedPayload.set(StrKey.decodeEd25519PublicKey(PROPOSED));
    new DataView(muxedPayload.buffer).setBigUint64(32, 42n);
    const muxed = StrKey.encodeMed25519PublicKey(muxedPayload as unknown as Buffer);
    expect(
      reviewPayoutDestinationChange({
        currentDestination: CURRENT,
        proposedDestination: muxed,
      })
    ).toMatchObject({
      ok: true,
      review: {
        proposed: { kind: "muxed_account" },
        risk: "elevated",
        warnings: ["DESTINATION_TYPE_CHANGED"],
      },
    });
  });

  it("rejects whitespace changes instead of silently normalizing them", () => {
    expect(
      reviewPayoutDestinationChange({
        currentDestination: CURRENT,
        proposedDestination: ` ${PROPOSED}`,
      })
    ).toMatchObject({
      ok: false,
      code: "PROPOSED_DESTINATION_INVALID",
      validationCode: "DESTINATION_WHITESPACE",
    });
  });
});
