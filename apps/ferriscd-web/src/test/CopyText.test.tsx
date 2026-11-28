import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CopyText } from "../ui/CopyText";
import { CopyToast } from "../ui/CopyToast";

describe("CopyText", () => {
  const writeText = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    writeText.mockClear();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
  });

  it("copies the full value when the displayed text is clicked", async () => {
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    render(
      <>
        <CopyToast />
        <CopyText
        value="sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e"
        display="sha256:9f2c…"
        label="rendered revision"
        />
      </>,
    );

    await user.click(screen.getByRole("button", { name: "Copy rendered revision" }));
    expect(writeText).toHaveBeenCalledWith(
      "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
    );
    expect(await screen.findByText("Copied")).toBeInTheDocument();
    expect(
      screen.getByText(
        "sha256:9f2c6ab1de5a4c8e70f0f9b8d1a2c3e4f5061728394a5b6c7d8e9f0a1b2c3d4e",
      ),
    ).toBeInTheDocument();
  });
});
