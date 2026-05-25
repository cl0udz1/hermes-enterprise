import { useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  Clock,
  FileText,
  KeyRound,
  RefreshCw,
  Shield,
  UserCheck,
  X,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Button } from "@nous-research/ui/ui/components/button";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { H2 } from "@/components/NouiTypography";
import { api } from "@/lib/api";
import type {
  EnterpriseApprovalSummary,
  EnterpriseAuditEventSummary,
  EnterpriseConsoleResponse,
  EnterpriseDoctorCheck,
  EnterpriseGrantSummary,
} from "@/lib/api";
import { PluginSlot } from "@/plugins";
import { Toast } from "@/components/Toast";
import { useToast } from "@/hooks/useToast";
import { usePageHeader } from "@/contexts/usePageHeader";
import { cn } from "@/lib/utils";

function formatTime(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function shortHash(value?: string): string {
  if (!value) return "-";
  return value.length > 14 ? `${value.slice(0, 10)}...${value.slice(-4)}` : value;
}

function statusTone(status: string): "success" | "warning" | "destructive" | "secondary" | "outline" {
  const normalized = status.toLowerCase();
  if (normalized === "pass" || normalized === "active" || normalized === "approved") return "success";
  if (normalized === "warn" || normalized === "staged" || normalized === "pending") return "warning";
  if (normalized === "fail" || normalized === "denied" || normalized === "revoked" || normalized === "expired") return "destructive";
  return "secondary";
}

function compactList(values: string[], fallback = "-"): string {
  if (!values.length) return fallback;
  return values.slice(0, 3).join(", ") + (values.length > 3 ? ` +${values.length - 3}` : "");
}

function safeArgsPreview(args: Record<string, unknown>): string {
  const entries = Object.entries(args);
  if (!entries.length) return "-";
  return entries
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join(" | ");
}

export default function EnterprisePage() {
  const [snapshot, setSnapshot] = useState<EnterpriseConsoleResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyStage, setBusyStage] = useState<string | null>(null);
  const { toast, showToast } = useToast();
  const { setAfterTitle, setEnd } = usePageHeader();

  const load = useCallback(() => {
    setLoading(true);
    api
      .getEnterpriseConsole()
      .then(setSnapshot)
      .catch((err) => showToast(`Enterprise console failed: ${err}`, "error"))
      .finally(() => setLoading(false));
  }, [showToast]);

  useEffect(() => {
    load();
  }, [load]);

  const overall = snapshot?.doctor.overall ?? "unknown";

  useLayoutEffect(() => {
    setAfterTitle(
      <span className="flex min-w-0 items-center gap-2">
        {loading && <Spinner className="shrink-0 text-base text-primary" />}
        <Badge tone={statusTone(overall)} className="text-[10px]">
          {overall}
        </Badge>
      </span>,
    );
    setEnd(
      <Button
        type="button"
        size="sm"
        outlined
        onClick={load}
        disabled={loading}
        title="Refresh"
        aria-label="Refresh enterprise console"
      >
        {loading ? <Spinner /> : <RefreshCw className="h-3 w-3" />}
        Refresh
      </Button>,
    );
    return () => {
      setAfterTitle(null);
      setEnd(null);
    };
  }, [load, loading, overall, setAfterTitle, setEnd]);

  const failedChecks = useMemo(
    () => snapshot?.doctor.checks.filter((item) => item.status === "fail") ?? [],
    [snapshot],
  );
  const warningChecks = useMemo(
    () => snapshot?.doctor.checks.filter((item) => item.status === "warn") ?? [],
    [snapshot],
  );

  const approve = async (stage: EnterpriseApprovalSummary) => {
    setBusyStage(stage.stage_id);
    try {
      await api.approveEnterpriseApproval(stage.stage_id, {
        approved_by: "dashboard-operator",
        ttl_minutes: 30,
        policy_version: "dashboard",
      });
      showToast(`Approved ${stage.tool_name}`, "success");
      load();
    } catch (err) {
      showToast(`Approval failed: ${err}`, "error");
    } finally {
      setBusyStage(null);
    }
  };

  const deny = async (stage: EnterpriseApprovalSummary) => {
    setBusyStage(stage.stage_id);
    try {
      await api.denyEnterpriseApproval(stage.stage_id, {
        denied_by: "dashboard-operator",
      });
      showToast(`Denied ${stage.tool_name}`, "success");
      load();
    } catch (err) {
      showToast(`Deny failed: ${err}`, "error");
    } finally {
      setBusyStage(null);
    }
  };

  if (loading && !snapshot) {
    return (
      <div className="flex items-center justify-center py-24">
        <Spinner className="text-2xl text-primary" />
      </div>
    );
  }

  return (
    <div className="flex min-w-0 max-w-full flex-col gap-5 normal-case">
      <PluginSlot name="enterprise:top" />
      <Toast toast={toast} />

      {snapshot && (
        <>
          <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              icon={Shield}
              label="Enterprise mode"
              value={snapshot.enabled ? snapshot.mode : "off"}
              tone={snapshot.enabled ? "success" : "warning"}
              badge={snapshot.enabled ? "enabled" : "disabled"}
            />
            <MetricCard
              icon={Clock}
              label="Pending approvals"
              value={String(snapshot.counts.approvals_pending)}
              tone={snapshot.counts.approvals_pending > 0 ? "warning" : "success"}
              badge={snapshot.counts.approvals_pending > 0 ? "review" : "clear"}
            />
            <MetricCard
              icon={KeyRound}
              label="Active grants"
              value={String(snapshot.counts.grants_active)}
              tone={snapshot.counts.grants_active > 0 ? "success" : "secondary"}
              badge={snapshot.counts.grants_active > 0 ? "active" : "none"}
            />
            <MetricCard
              icon={Activity}
              label="Audit events"
              value={String(snapshot.counts.audit_total)}
              tone="secondary"
              badge="ledger"
            />
          </div>

          <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(320px,0.75fr)]">
            <ApprovalQueue
              approvals={snapshot.pending_approvals}
              busyStage={busyStage}
              onApprove={approve}
              onDeny={deny}
            />

            <ControlHealth
              checks={snapshot.doctor.checks}
              failedChecks={failedChecks}
              warningChecks={warningChecks}
              counts={snapshot.counts}
            />
          </div>

          <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-2">
            <GrantList grants={snapshot.recent_grants} />
            <AuditTimeline events={snapshot.recent_events} />
          </div>
        </>
      )}

      <PluginSlot name="enterprise:bottom" />
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
  badge,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  tone: "success" | "warning" | "destructive" | "secondary";
  badge: string;
}) {
  return (
    <Card className="min-w-0 overflow-hidden">
      <CardContent className="flex items-center gap-3 py-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center border border-border bg-secondary/40">
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-xs text-muted-foreground">{label}</p>
          <div className="mt-1 flex min-w-0 items-center gap-2">
            <span className="truncate font-mono-ui text-lg leading-none">{value}</span>
            <Badge tone={tone} className="text-[10px]">
              {badge}
            </Badge>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ApprovalQueue({
  approvals,
  busyStage,
  onApprove,
  onDeny,
}: {
  approvals: EnterpriseApprovalSummary[];
  busyStage: string | null;
  onApprove: (stage: EnterpriseApprovalSummary) => void;
  onDeny: (stage: EnterpriseApprovalSummary) => void;
}) {
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <UserCheck className="h-4 w-4" />
        Approval queue ({approvals.length})
      </H2>

      {approvals.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No staged actions.
          </CardContent>
        </Card>
      ) : (
        approvals.map((stage) => {
          const busy = busyStage === stage.stage_id;
          return (
            <Card key={stage.stage_id} className="min-w-0 overflow-hidden">
              <CardContent className="grid gap-4 py-4 lg:grid-cols-[minmax(0,1fr)_auto]">
                <div className="min-w-0">
                  <div className="mb-2 flex min-w-0 flex-wrap items-center gap-2">
                    <span className="truncate font-medium text-sm">{stage.tool_name}</span>
                    <Badge tone={statusTone(stage.risk_tier)}>{stage.risk_tier || "risk"}</Badge>
                    <Badge tone="outline">{stage.subject_id}</Badge>
                  </div>

                  <dl className="grid min-w-0 gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                    <KeyValue label="Stage" value={shortHash(stage.stage_id)} mono />
                    <KeyValue label="Action" value={shortHash(stage.action_hash)} mono />
                    <KeyValue label="Effects" value={compactList(stage.requested_side_effects)} />
                    <KeyValue label="Created" value={formatTime(stage.created_at)} />
                  </dl>

                  <div className="mt-3 min-w-0 border-t border-border pt-3">
                    <p className="truncate font-mono-ui text-xs text-foreground">
                      {safeArgsPreview(stage.safe_args)}
                    </p>
                    <p className="mt-1 truncate text-xs text-muted-foreground">
                      {compactList(stage.detectors)}
                    </p>
                  </div>
                </div>

                <div className="flex items-start justify-end gap-1">
                  <Button
                    size="sm"
                    onClick={() => onApprove(stage)}
                    disabled={busy}
                    title="Approve"
                    aria-label={`Approve ${stage.tool_name}`}
                  >
                    {busy ? <Spinner /> : <Check className="h-3 w-3" />}
                    Approve
                  </Button>
                  <Button
                    size="sm"
                    outlined
                    destructive
                    onClick={() => onDeny(stage)}
                    disabled={busy}
                    title="Deny"
                    aria-label={`Deny ${stage.tool_name}`}
                  >
                    <X className="h-3 w-3" />
                    Deny
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })
      )}
    </section>
  );
}

function ControlHealth({
  checks,
  failedChecks,
  warningChecks,
  counts,
}: {
  checks: EnterpriseDoctorCheck[];
  failedChecks: EnterpriseDoctorCheck[];
  warningChecks: EnterpriseDoctorCheck[];
  counts: EnterpriseConsoleResponse["counts"];
}) {
  const priorityChecks = [...failedChecks, ...warningChecks, ...checks.filter((item) => item.status === "pass")].slice(0, 7);

  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <AlertTriangle className="h-4 w-4" />
        Control health
      </H2>

      <Card className="min-w-0 overflow-hidden">
        <CardHeader className="px-4 py-3">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <Badge tone="success">{counts.doctor_pass} pass</Badge>
            <Badge tone="warning">{counts.doctor_warn} warn</Badge>
            <Badge tone="destructive">{counts.doctor_fail} fail</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 py-0 pb-4">
          {priorityChecks.map((check) => (
            <div
              key={check.name}
              className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-start gap-2 border-t border-border pt-2 first:border-t-0 first:pt-0"
            >
              <Badge tone={statusTone(check.status)} className="text-[10px]">
                {check.status}
              </Badge>
              <div className="min-w-0">
                <p className="truncate text-sm">{check.label || check.name}</p>
                <p className="line-clamp-2 text-xs text-muted-foreground">
                  {check.detail || check.remediation || "-"}
                </p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </section>
  );
}

function GrantList({ grants }: { grants: EnterpriseGrantSummary[] }) {
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <KeyRound className="h-4 w-4" />
        Recent grants ({grants.length})
      </H2>

      <Card className="min-w-0 overflow-hidden">
        <CardContent className="p-0">
          {grants.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No grants.</p>
          ) : (
            <div className="divide-y divide-border">
              {grants.map((grant) => (
                <div key={grant.grant_id} className="grid gap-2 px-4 py-3 text-sm">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <Badge tone={statusTone(grant.status)}>{grant.status}</Badge>
                    <span className="truncate font-mono-ui text-xs">
                      {shortHash(grant.grant_id)}
                    </span>
                    <span className="truncate text-xs text-muted-foreground">
                      {grant.tool_name || "secret"}
                    </span>
                  </div>
                  <dl className="grid min-w-0 gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                    <KeyValue label="Subject" value={grant.subject_id} />
                    <KeyValue label="Approver" value={grant.approved_by || "-"} />
                    <KeyValue label="Expires" value={formatTime(grant.expires_at)} />
                    <KeyValue label="Actions" value={compactList(grant.actions)} />
                  </dl>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function AuditTimeline({ events }: { events: EnterpriseAuditEventSummary[] }) {
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <FileText className="h-4 w-4" />
        Audit timeline ({events.length})
      </H2>

      <Card className="min-w-0 overflow-hidden">
        <CardContent className="p-0">
          {events.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No audit events.
            </p>
          ) : (
            <div className="divide-y divide-border">
              {events.map((event) => (
                <div key={event.event_id} className="grid min-w-0 gap-1 px-4 py-3">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <Badge tone="outline">{event.event_type}</Badge>
                    <span className="truncate font-mono-ui text-xs text-muted-foreground">
                      {shortHash(event.event_id)}
                    </span>
                    <span className="ml-auto text-xs text-muted-foreground">
                      {formatTime(event.created_at)}
                    </span>
                  </div>
                  <p className="truncate text-sm">{event.redacted_preview}</p>
                  <p className="truncate font-mono-ui text-xs text-muted-foreground">
                    {event.subject_id} | {shortHash(event.action_id)}
                  </p>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function KeyValue({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-[0.12em] opacity-60">{label}</dt>
      <dd
        className={cn(
          "truncate text-xs text-foreground",
          mono && "font-mono-ui",
        )}
      >
        {value || "-"}
      </dd>
    </div>
  );
}
