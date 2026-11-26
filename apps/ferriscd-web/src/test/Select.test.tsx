import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Select } from "../ui/Select";

const OPTIONS = [
  { value: "ALL", label: "All Kinds" },
  { value: "Pod", label: "Pod" },
  { value: "Service", label: "Service" },
];

function Harness({ onChange = vi.fn() }: { onChange?: (v: string) => void }) {
  const [value, setValue] = useState("ALL");
  return (
    <Select
      aria-label="Filter by kind"
      value={value}
      options={OPTIONS}
      onChange={(next) => {
        setValue(next);
        onChange(next);
      }}
    />
  );
}

describe("Select (themed combobox)", () => {
  it("opens as a dark-themed listbox and selects an option with the mouse", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);

    const trigger = screen.getByRole("combobox", { name: /Filter by kind/i });
    expect(trigger).toHaveTextContent("All Kinds");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();

    await user.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("listbox")).toBeInTheDocument();
    expect(screen.getAllByRole("option")).toHaveLength(3);
    expect(screen.getByRole("option", { name: "All Kinds" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    await user.click(screen.getByRole("option", { name: "Pod" }));
    expect(onChange).toHaveBeenCalledWith("Pod");
    expect(trigger).toHaveTextContent("Pod");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  });

  it("supports keyboard navigation with Enter and Escape", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);

    const trigger = screen.getByRole("combobox", { name: /Filter by kind/i });
    trigger.focus();

    await user.keyboard("{ArrowDown}");
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    await user.keyboard("{ArrowDown}{Enter}");
    expect(onChange).toHaveBeenCalledWith("Pod");
    expect(trigger).toHaveTextContent("Pod");

    await user.keyboard("{ArrowDown}{Escape}");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(trigger).toHaveFocus();
  });

  it("closes when clicking outside without changing the selection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <div>
        <Harness onChange={onChange} />
        <button type="button">elsewhere</button>
      </div>,
    );

    await user.click(screen.getByRole("combobox", { name: /Filter by kind/i }));
    expect(screen.getByRole("listbox")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "elsewhere" }));
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
  });
});
