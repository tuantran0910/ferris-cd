import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiErrorAlert } from "../ui/ApiErrorBoundary";

describe("ApiErrorAlert cancellation", () => {
  it("renders nothing for a cancelled query", () => {
    const cancelled = new Error("cancelled");
    cancelled.name = "CancelledError";
    const { container } = render(<ApiErrorAlert error={cancelled} />);
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("still renders a real failure", () => {
    render(<ApiErrorAlert error={new Error("boom")} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
