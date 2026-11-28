import type { BadgeTone } from "./Badge";

/** Bounded, semantic colour per Kubernetes kind (never a per-name colour). */
export function kindTone(kind: string | null | undefined): BadgeTone {
  switch ((kind ?? "").toLowerCase()) {
    case "namespace":
      return "violet";
    case "configmap":
      return "info";
    case "secret":
      return "danger";
    case "service":
      return "success";
    case "deployment":
    case "statefulset":
    case "daemonset":
    case "replicaset":
    case "pod":
      return "fuchsia";
    case "job":
    case "cronjob":
      return "orange";
    case "ingress":
    case "httproute":
      return "warning";
    default:
      return "neutral";
  }
}
