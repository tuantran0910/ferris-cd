import { FolderGit2, Search, ShieldCheck, Workflow } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ProjectView } from "../../api/types";
import { ApiErrorAlert } from "../../ui/ApiErrorBoundary";
import { Badge } from "../../ui/Badge";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/EmptyState";
import { LiveRegion } from "../../ui/LiveRegion";
import { Skeleton } from "../../ui/Skeleton";
import { normalizeSyncStatus } from "../../ui/StatusBadges";
import { useApplications } from "../applications/hooks";
import { useProjects } from "./hooks";

/**
 * `/projects` — the tenancy boundaries of the control plane (`T17.3`).
 *
 * Read-only view of every `AppProject` this identity may see (`GET /api/v1/projects` is already
 * filtered server-side, so an invisible project is simply absent — never rendered as "restricted").
 * Each card answers the questions an operator asks before deploying: which repositories, which
 * namespaces, which destination `cluster/namespace`, which ServiceAccounts, and how much of the fleet
 * lives in it.
 *
 * Search is a client-side filter over facts the response already carries; it never re-queries the
 * cluster. Every row is a `Link` to the filtered application list, so "which applications are in this
 * project?" is one click (and the filter lives in the URL, so it survives a reload).
 */
export function ProjectsPage() {
  const [search, setSearch] = useState("");
  const projectsQuery = useProjects();
  // The project → application rollup comes from the same filtered list the Applications page shows.
  const applicationsQuery = useApplications();

  const projects = useMemo(
    () => projectsQuery.data?.items ?? [],
    [projectsQuery.data],
  );
  const applications = useMemo(
    () => applicationsQuery.data?.items ?? [],
    [applicationsQuery.data],
  );

  const countsByProject = useMemo(() => {
    const counts = new Map<string, { total: number; outOfSync: number }>();
    for (const app of applications) {
      const current = counts.get(app.project) ?? { total: 0, outOfSync: 0 };
      current.total += 1;
      if (normalizeSyncStatus(app.sync?.status) === "OutOfSync") {
        current.outOfSync += 1;
      }
      counts.set(app.project, current);
    }
    return counts;
  }, [applications]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) {
      return projects;
    }
    return projects.filter((project) =>
      [
        project.name,
        project.description ?? "",
        ...(project.sourceRepos ?? []),
        ...(project.sourceNamespaces ?? []),
        ...(project.destinations ?? []),
        ...(project.allowedServiceAccounts ?? []),
      ]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [projects, search]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Projects
        </h1>
        <p className="mt-1 text-xs text-slate-300">
          {projects.length === 1
            ? "1 AppProject visible to your identity"
            : `${projects.length} AppProjects visible to your identity`}
          {" — "}
          repository, namespace, destination and ServiceAccount allow-lists.
        </p>
      </div>

      <LiveRegion
        message={
          projectsQuery.isSuccess
            ? `Showing ${filtered.length} of ${projects.length} projects.`
            : ""
        }
        data-testid="projects-live-region"
      />

      <div className="relative max-w-md">
        <Search
          aria-hidden="true"
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
        />
        <input
          type="search"
          aria-label="Search projects"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search by project, repo, namespace, cluster, or ServiceAccount..."
          className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-xs text-slate-100 transition-colors placeholder-slate-400 focus:border-indigo-400 focus:outline-none"
        />
      </div>

      {projectsQuery.error && (
        <ApiErrorAlert
          error={projectsQuery.error}
          onRetry={() => void projectsQuery.refetch()}
        />
      )}

      {projectsQuery.isLoading ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {Array.from({ length: 2 }).map((_, index) => (
            <Skeleton key={index} className="h-56" />
          ))}
        </div>
      ) : !projectsQuery.data ? null : filtered.length === 0 ? (
        <EmptyState size="lg">
          <p>
            {projects.length === 0
              ? "No AppProjects are visible to your identity."
              : "No AppProjects match the current search."}
          </p>
        </EmptyState>
      ) : (
        <ul className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {filtered.map((project) => (
            <li key={project.name}>
              <ProjectCard
                project={project}
                counts={countsByProject.get(project.name)}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ProjectCard({
  project,
  counts,
}: {
  project: ProjectView;
  counts?: { total: number; outOfSync: number };
}) {
  const applicationsLink = {
    pathname: "/",
    search: `?${new URLSearchParams({ project: project.name }).toString()}`,
  };

  return (
    <Card className="flex h-full flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-base font-semibold text-slate-100">
            <FolderGit2 aria-hidden="true" className="h-4 w-4 text-indigo-400" />
            <Link
              to={applicationsLink}
              className="truncate rounded hover:underline"
              title={`Applications in project ${project.name}`}
            >
              {project.name}
            </Link>
          </h2>
          {project.description && (
            <p className="mt-1 break-words text-xs text-slate-300">
              {project.description}
            </p>
          )}
        </div>
        <Badge tone="info" size="sm" data-testid={`project-app-count-${project.name}`}>
          {applicationCountLabel(counts?.total ?? 0)}
        </Badge>
      </div>

      <dl className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
        <FactList
          icon={<Workflow aria-hidden="true" className="h-3.5 w-3.5 text-sky-300" />}
          title="Source repositories"
          values={project.sourceRepos ?? []}
          testId={`project-source-repos-${project.name}`}
        />
        <FactList
          title="Source namespaces"
          values={project.sourceNamespaces ?? []}
          testId={`project-source-namespaces-${project.name}`}
        />
        <FactList
          icon={<ShieldCheck aria-hidden="true" className="h-3.5 w-3.5 text-emerald-300" />}
          title="Destinations"
          values={project.destinations ?? []}
          testId={`project-destinations-${project.name}`}
        />
        <FactList
          title="Allowed ServiceAccounts"
          values={project.allowedServiceAccounts ?? []}
          testId={`project-service-accounts-${project.name}`}
        />
      </dl>

      <p className="mt-auto text-xs text-slate-300">
        {counts && counts.outOfSync > 0 ? (
          <>
            <span className="font-semibold text-amber-200">
              {counts.outOfSync} out of sync
            </span>
            {" of "}
            {applicationCountLabel(counts.total)}.{" "}
          </>
        ) : (
          <>All {applicationCountLabel(counts?.total ?? 0)} in sync. </>
        )}
        <Link
          to={applicationsLink}
          className="font-medium text-indigo-300 hover:underline"
        >
          View applications
        </Link>
      </p>
    </Card>
  );
}

/** "1 application" / "3 applications" — a count is always a sentence, never a bare number. */
function applicationCountLabel(count: number): string {
  return count === 1 ? "1 application" : `${count} applications`;
}

/**
 * One allow-list. An empty list is *not* hidden: "no repositories allowed" is the most important
 * fact on the card, so it is stated (and `none` is a word, not a blank space).
 */
function FactList({
  icon,
  title,
  values,
  testId,
}: {
  icon?: ReactNode;
  title: string;
  values: string[];
  testId: string;
}) {
  return (
    <div data-testid={testId}>
      <dt className="flex items-center gap-1.5 font-medium text-slate-200">
        {icon}
        {title}
      </dt>
      <dd className="mt-1">
        {values.length === 0 ? (
          <span className="text-slate-400">none</span>
        ) : (
          <ul className="flex flex-wrap gap-1.5">
            {values.map((value) => (
              <li key={value}>
                <code className="break-all rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] text-slate-200">
                  {value}
                </code>
              </li>
            ))}
          </ul>
        )}
      </dd>
    </div>
  );
}
