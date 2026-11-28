import {
  Boxes,
  Command as CommandIcon,
  FileDiff,
  History,
  Layers,
  ListChecks,
  Search,
  Server,
  TriangleAlert,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import type {
  ApplicationSummary,
  ClusterView,
  ProjectView,
} from "../api/types";
import { Modal } from "../ui/Modal";
import { useApplications } from "../features/applications/hooks";
import { useClusters } from "../features/clusters/hooks";
import { useProjects } from "../features/projects/hooks";
import { useModalBehavior } from "../features/sync/useModalBehavior";

/** How many entries one group contributes, so a 250-application fleet stays navigable. */
const MAX_ITEMS_PER_GROUP = 8;

/** `/applications/:namespace/:name` — the only route that owns detail tabs. */
const DETAIL_ROUTE = /^\/applications\/([^/]+)\/([^/]+)\/?$/;

type DetailTab = "resources" | "diff" | "events" | "conditions" | "history";

interface PaletteItem {
  id: string;
  label: string;
  hint?: string;
  group: string;
  icon?: ReactNode;
  /** Router target: a pathname plus (optionally) a query string. */
  to: { pathname: string; search?: string };
}

function searchFor(params: Record<string, string>): string {
  return `?${new URLSearchParams(params).toString()}`;
}

/**
 * Registers the global `Cmd+K` / `Ctrl+K` shortcut (`T17.3`).
 *
 * The listener is on `document` rather than on a container so the palette is reachable from every
 * page — including while the operator is scrolled to the bottom of a long diff — and it
 * `preventDefault()`s the browser's own binding so one chord means one thing.
 */
export function useCommandPaletteShortcut(onToggle: () => void) {
  const onToggleRef = useRef(onToggle);
  useEffect(() => {
    onToggleRef.current = onToggle;
  }, [onToggle]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey) {
        return;
      }
      if (event.key.toLowerCase() !== "k") {
        return;
      }
      event.preventDefault();
      // Never open a second focus trap on top of Sync/Rollback (Escape would close both); the
      // palette's own dialog is marked so Cmd+K still toggles it closed.
      const paletteOpen = document.querySelector('[data-command-palette]') !== null;
      if (!paletteOpen && document.querySelector('[role="dialog"]')) {
        return;
      }
      onToggleRef.current();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
}

/**
 * Accessible command palette (`Cmd+K` / `Ctrl+K`, `T17.3`).
 *
 * # Why a palette
 *
 * During an incident an operator knows *what* they want ("the payments diff") long before they know
 * where it lives in the navigation tree. This dialog turns that into two keystrokes, reachable from
 * every page — which is why the app shell owns its open/closed state and the global shortcut.
 *
 * # Keyboard-first, WCAG 2.2 AA
 *
 * - `Escape` closes it and focus returns to whatever was focused before, `Tab` stays inside it (both
 *   come from [`useModalBehavior`], the same trap the Sync/Rollback modals use).
 * - It implements the ARIA combobox + listbox pattern: the input keeps focus, the active option is
 *   exposed through `aria-activedescendant`, and `Arrow`/`Home`/`End`/`Enter` are handled explicitly.
 * - Results are grouped and each result states its own kind, so the list is readable as text.
 * - The result count is announced in a live region as the query narrows the list.
 */
export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!open) {
    return null;
  }
  return <CommandPaletteDialog onClose={() => onOpenChange(false)} />;
}

function CommandPaletteDialog({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);
  const baseId = useId();
  const listId = `${baseId}-listbox`;
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  // Mounted only while open, so these three queries exist only for the duration of the dialog: a
  // dashboard that never opens the palette never pays for an `AppProject`/cluster read.
  const applicationsQuery = useApplications();
  const projectsQuery = useProjects();
  const clustersQuery = useClusters();

  useModalBehavior(true, dialogRef, onClose);

  const groups = useMemo(
    () =>
      buildGroups({
        query,
        pathname,
        applications: applicationsQuery.data?.items ?? [],
        projects: projectsQuery.data?.items ?? [],
        clusters: clustersQuery.data?.items ?? [],
      }),
    [
      query,
      pathname,
      applicationsQuery.data,
      projectsQuery.data,
      clustersQuery.data,
    ],
  );
  const items = useMemo(() => groups.flatMap((group) => group.items), [groups]);

  const clampedIndex = items.length === 0 ? -1 : Math.min(activeIndex, items.length - 1);
  const activeItem = clampedIndex >= 0 ? items[clampedIndex] : undefined;

  const activate = useCallback(
    (item: PaletteItem | undefined) => {
      if (!item) {
        return;
      }
      navigate(
        item.to.search
          ? { pathname: item.to.pathname, search: item.to.search }
          : item.to.pathname,
      );
      onClose();
    },
    [navigate, onClose],
  );

  useEffect(() => {
    if (!activeItem) {
      return;
    }
    // jsdom (tests) does not implement `scrollIntoView`; optional call keeps this a no-op there.
    listRef.current
      ?.querySelector<HTMLElement>(`[data-index="${clampedIndex}"]`)
      ?.scrollIntoView?.({ block: "nearest" });
  }, [activeItem, clampedIndex]);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        if (items.length > 0) {
          setActiveIndex((index) => (Math.min(index, items.length - 1) + 1) % items.length);
        }
        return;
      case "ArrowUp":
        event.preventDefault();
        if (items.length > 0) {
          setActiveIndex(
            (index) => (Math.min(index, items.length - 1) + items.length - 1) % items.length,
          );
        }
        return;
      case "Home":
        event.preventDefault();
        setActiveIndex(0);
        return;
      case "End":
        event.preventDefault();
        setActiveIndex(Math.max(items.length - 1, 0));
        return;
      case "Enter":
        event.preventDefault();
        activate(activeItem);
        return;
      default:
        return;
    }
  };

  return (
    <Modal
      open
      labelledBy="command-palette-title"
      dialogRef={dialogRef}
      panelClassName="max-w-xl"
      onBackdropClick={onClose}
    >
      <h2 id="command-palette-title" data-command-palette="true" className="sr-only">
        Command palette
      </h2>

      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <Search aria-hidden="true" className="h-4 w-4 shrink-0 text-ink-body" />
        <input
          // No `autoFocus`: the focus trap focuses the first focusable element (this input) when the
          // dialog opens and records *what was focused before* to restore on close. An `autoFocus`
          // runs during commit, before that effect, and would make it record the input itself.
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={
            activeItem ? `${baseId}-option-${clampedIndex}` : undefined
          }
          aria-label="Search applications, projects, clusters and views"
          placeholder="Jump to an application, project, cluster, or view..."
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActiveIndex(0);
          }}
          onKeyDown={onKeyDown}
          className="w-full rounded-lg border border-control bg-canvas px-3 py-2 text-sm text-ink-strong transition-colors placeholder-hint focus:border-indigo-400 focus:outline-none"
        />
        <kbd className="hidden shrink-0 rounded border border-control bg-surface px-1.5 py-0.5 font-mono text-[10px] text-ink-body sm:block">
          Esc
        </kbd>
      </div>

      <div className="max-h-80 overflow-y-auto px-2 py-2">
        <ul ref={listRef} id={listId} role="listbox" aria-label="Command palette results">
          {groups.map((group) => (
            <li key={group.name} role="presentation">
              <ul role="group" aria-label={group.name}>
                {group.items.map((item) => {
                  const index = items.indexOf(item);
                  const active = index === clampedIndex;
                  return (
                    <li
                      key={item.id}
                      id={`${baseId}-option-${index}`}
                      data-index={index}
                      data-testid={`palette-item-${item.id}`}
                      role="option"
                      aria-selected={active}
                      onMouseEnter={() => setActiveIndex(index)}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => activate(item)}
                      className={`flex cursor-pointer items-center justify-between gap-3 rounded-lg px-2.5 py-2 text-xs ${
                        active ? "bg-elevated text-ink-strong" : "text-ink"
                      }`}
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <span aria-hidden="true" className="shrink-0 text-ink-body">
                          {item.icon}
                        </span>
                        <span className="truncate font-medium">{item.label}</span>
                      </span>
                      <span className="shrink-0 text-[11px] text-ink-body">{item.hint}</span>
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
          {items.length === 0 && (
            // A `listbox` must contain at least one option, and an empty state is not a `role=
            // presentation` decoration: a disabled option keeps the ARIA structure valid while
            // telling the screen reader there is nothing to choose.
            <li
              role="option"
              aria-disabled="true"
              aria-selected="false"
              className="px-3 py-6 text-center text-xs text-ink"
            >
              No applications, projects, clusters, or views match “{query}”.
            </li>
          )}
        </ul>
      </div>

      <p
        role="status"
        aria-live="polite"
        data-testid="command-palette-status"
        className="border-t border-line px-4 py-2 text-[11px] text-ink-body"
      >
        {items.length === 0
          ? "No results."
          : `${items.length} results. Use the arrow keys to choose, Enter to open, Escape to close.`}
      </p>
    </Modal>
  );
}

function buildGroups({
  query,
  pathname,
  applications,
  projects,
  clusters,
}: {
  query: string;
  pathname: string;
  applications: ApplicationSummary[];
  projects: ProjectView[];
  clusters: ClusterView[];
}): { name: string; items: PaletteItem[] }[] {
  const detailMatch = DETAIL_ROUTE.exec(pathname);
  const groups: { name: string; items: PaletteItem[] }[] = [];

  const applicationItems: PaletteItem[] = applications.map((app) => ({
    id: `application-${app.namespace}-${app.name}`,
    label: `${app.namespace}/${app.name}`,
    hint: `application · ${app.project} · ${app.sync?.status ?? "Unknown"}`,
    group: "Applications",
    icon: <Boxes className="h-3.5 w-3.5" />,
    to: {
      pathname: `/applications/${encodeURIComponent(app.namespace)}/${encodeURIComponent(app.name)}`,
    },
  }));

  const projectItems: PaletteItem[] = projects.map((project) => ({
    id: `project-${project.name}`,
    label: project.name,
    hint: `project${project.description ? ` · ${project.description}` : ""}`,
    group: "Projects",
    icon: <Layers className="h-3.5 w-3.5" />,
    to: { pathname: "/", search: searchFor({ project: project.name }) },
  }));

  const clusterItems: PaletteItem[] = clusters.map((cluster) => ({
    id: `cluster-${cluster.name}`,
    label: cluster.name,
    hint: cluster.inCluster ? "cluster · in-cluster" : "cluster · remote",
    group: "Clusters",
    icon: <Server className="h-3.5 w-3.5" />,
    to: { pathname: "/", search: searchFor({ q: cluster.name }) },
  }));

  const viewItems: PaletteItem[] = [
    {
      id: "view-applications",
      label: "Applications",
      hint: "view",
      group: "Views",
      icon: <Boxes className="h-3.5 w-3.5" />,
      to: { pathname: "/" },
    },
    {
      id: "view-projects",
      label: "Projects",
      hint: "view",
      group: "Views",
      icon: <Layers className="h-3.5 w-3.5" />,
      to: { pathname: "/projects" },
    },
    {
      id: "view-clusters",
      label: "Clusters",
      hint: "view",
      group: "Views",
      icon: <Server className="h-3.5 w-3.5" />,
      to: { pathname: "/clusters" },
    },
  ];

  // Detail tabs are only addressable while a detail page is open, and the palette is how an
  // operator reaches them without hunting for the tab strip.
  if (detailMatch) {
    const [, namespace, name] = detailMatch;
    const detailPath = `/applications/${namespace}/${name}`;
    const tabs: { tab: DetailTab; label: string; icon: ReactNode }[] = [
      { tab: "resources", label: "Resource graph", icon: <Boxes className="h-3.5 w-3.5" /> },
      { tab: "diff", label: "Live diff", icon: <FileDiff className="h-3.5 w-3.5" /> },
      { tab: "events", label: "Events", icon: <TriangleAlert className="h-3.5 w-3.5" /> },
      { tab: "conditions", label: "Conditions", icon: <ListChecks className="h-3.5 w-3.5" /> },
      { tab: "history", label: "History", icon: <History className="h-3.5 w-3.5" /> },
    ];
    for (const { tab, label, icon } of tabs) {
      viewItems.push({
        id: `view-${tab}`,
        label,
        hint: `tab · ${namespace}/${name}`,
        group: "Views",
        icon,
        to: { pathname: detailPath, search: searchFor({ tab }) },
      });
    }
  }

  const needle = query.trim().toLowerCase();
  const matches = (item: PaletteItem) =>
    needle.length === 0 ||
    `${item.label} ${item.hint ?? ""} ${item.group}`.toLowerCase().includes(needle);

  const push = (name: string, items: PaletteItem[]) => {
    const matched = items.filter(matches).slice(0, MAX_ITEMS_PER_GROUP);
    if (matched.length > 0) {
      groups.push({ name, items: matched });
    }
  };

  // Applications first (the most common jump), then the navigation targets.
  push("Applications", applicationItems);
  push("Projects", projectItems);
  push("Clusters", clusterItems);
  push("Views", viewItems);

  return groups;
}

/** The keyboard hint shown in the header button's tooltip/label. */
export const COMMAND_PALETTE_HINT = "⌘K / Ctrl+K";

/** Icon used by the shell's "open the palette" affordance. */
export const CommandPaletteIcon = CommandIcon;
