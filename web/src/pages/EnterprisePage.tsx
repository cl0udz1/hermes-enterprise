import { useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  Clock,
  Download,
  Eye,
  FileText,
  KeyRound,
  RefreshCw,
  Shield,
  UserCheck,
  UserPlus,
  UserRound,
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Button } from "@nous-research/ui/ui/components/button";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { H2 } from "@/components/NouiTypography";
import { api } from "@/lib/api";
import type {
  EnterpriseAssignmentSummary,
  EnterpriseAssignmentsResponse,
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

function parseList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatSafeValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function safeArgsPreview(args: Record<string, unknown>): string {
  const entries = Object.entries(args);
  if (!entries.length) return "-";
  return entries
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${formatSafeValue(value)}`)
    .join(" | ");
}

function downloadJson(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function defaultOperatorId(): string {
  if (typeof window === "undefined") return "dashboard-operator";
  return window.localStorage.getItem("hermes.enterprise.operator") || "dashboard-operator";
}

export default function EnterprisePage() {
  const [snapshot, setSnapshot] = useState<EnterpriseConsoleResponse | null>(null);
  const [assignments, setAssignments] = useState<EnterpriseAssignmentsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyStage, setBusyStage] = useState<string | null>(null);
  const [busyAssignment, setBusyAssignment] = useState<string | null>(null);
  const [selectedStageId, setSelectedStageId] = useState<string | null>(null);
  const [operatorId, setOperatorId] = useState(defaultOperatorId);
  const [approvalReason, setApprovalReason] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState(30);
  const [assignmentSubject, setAssignmentSubject] = useState("");
  const [assignmentAgent, setAssignmentAgent] = useState("");
  const [assignmentProfile, setAssignmentProfile] = useState("default");
  const [assignmentRole, setAssignmentRole] = useState("employee");
  const [assignmentReason, setAssignmentReason] = useState("");
  const [assignmentSurfaces, setAssignmentSurfaces] = useState("dashboard, cli, tui, gateway");
  const [assignmentWorkspace, setAssignmentWorkspace] = useState("");
  const { toast, showToast } = useToast();
  const { setAfterTitle, setEnd } = usePageHeader();

  const load = useCallback(() => {
    setLoading(true);
    Promise.allSettled([
      api.getEnterpriseConsole(),
      api.getEnterpriseAssignments(),
    ])
      .then(([consoleResult, assignmentResult]) => {
        if (consoleResult.status === "fulfilled") {
          setSnapshot(consoleResult.value);
        } else {
          showToast(`Enterprise console failed: ${consoleResult.reason}`, "error");
        }
        if (assignmentResult.status === "fulfilled") {
          setAssignments(assignmentResult.value);
          if (!assignmentProfile && assignmentResult.value.profiles[0]?.name) {
            setAssignmentProfile(assignmentResult.value.profiles[0].name);
          }
        } else {
          showToast(`Assignments failed: ${assignmentResult.reason}`, "error");
        }
      })
      .finally(() => setLoading(false));
  }, [showToast]);

  useEffect(() => {
    load();
  }, [load]);

  const overall = snapshot?.doctor.overall ?? "unknown";
  const selectedStage = useMemo(
    () =>
      snapshot?.pending_approvals.find((stage) => stage.stage_id === selectedStageId) ??
      snapshot?.pending_approvals[0] ??
      null,
    [selectedStageId, snapshot],
  );

  useEffect(() => {
    if (!snapshot) return;
    if (snapshot.pending_approvals.length === 0) {
      setSelectedStageId(null);
      return;
    }
    if (!selectedStageId || !snapshot.pending_approvals.some((stage) => stage.stage_id === selectedStageId)) {
      setSelectedStageId(snapshot.pending_approvals[0].stage_id);
    }
  }, [selectedStageId, snapshot]);

  const exportEvidence = useCallback(
    async (stage?: EnterpriseApprovalSummary | null) => {
      try {
        const bundle = await api.getEnterpriseEvidence(stage?.stage_id);
        const suffix = stage?.stage_id ? shortHash(stage.stage_id).replace(/[^a-z0-9-]/gi, "") : "console";
        downloadJson(`hermes-enterprise-evidence-${suffix}.json`, bundle);
        showToast("Evidence exported", "success");
      } catch (err) {
        showToast(`Evidence export failed: ${err}`, "error");
      }
    },
    [showToast],
  );

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
      <span className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          outlined
          onClick={() => exportEvidence()}
          title="Export evidence"
          aria-label="Export enterprise evidence"
        >
          <Download className="h-3 w-3" />
          Export
        </Button>
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
        </Button>
      </span>,
    );
    return () => {
      setAfterTitle(null);
      setEnd(null);
    };
  }, [exportEvidence, load, loading, overall, setAfterTitle, setEnd]);

  const failedChecks = useMemo(
    () => snapshot?.doctor.checks.filter((item) => item.status === "fail") ?? [],
    [snapshot],
  );
  const warningChecks = useMemo(
    () => snapshot?.doctor.checks.filter((item) => item.status === "warn") ?? [],
    [snapshot],
  );

  const approve = async (stage: EnterpriseApprovalSummary) => {
    const reason = approvalReason.trim();
    const operator = operatorId.trim() || "dashboard-operator";
    if (!reason) {
      showToast("Approval reason is required", "error");
      return;
    }
    setBusyStage(stage.stage_id);
    try {
      window.localStorage.setItem("hermes.enterprise.operator", operator);
      await api.approveEnterpriseApproval(stage.stage_id, {
        approved_by: operator,
        ttl_minutes: ttlMinutes,
        policy_version: "dashboard",
        reason,
      });
      showToast(`Approved ${stage.tool_name}`, "success");
      setApprovalReason("");
      load();
    } catch (err) {
      showToast(`Approval failed: ${err}`, "error");
    } finally {
      setBusyStage(null);
    }
  };

  const deny = async (stage: EnterpriseApprovalSummary) => {
    const reason = approvalReason.trim();
    const operator = operatorId.trim() || "dashboard-operator";
    if (!reason) {
      showToast("Denial reason is required", "error");
      return;
    }
    setBusyStage(stage.stage_id);
    try {
      window.localStorage.setItem("hermes.enterprise.operator", operator);
      await api.denyEnterpriseApproval(stage.stage_id, {
        denied_by: operator,
        reason,
      });
      showToast(`Denied ${stage.tool_name}`, "success");
      setApprovalReason("");
      load();
    } catch (err) {
      showToast(`Deny failed: ${err}`, "error");
    } finally {
      setBusyStage(null);
    }
  };

  const createAssignment = async () => {
    const subject = assignmentSubject.trim();
    const agent = assignmentAgent.trim();
    const reason = assignmentReason.trim();
    const operator = operatorId.trim() || "dashboard-operator";
    if (!subject || !agent || !reason) {
      showToast("Subject, agent, and assignment reason are required", "error");
      return;
    }
    setBusyAssignment("create");
    try {
      window.localStorage.setItem("hermes.enterprise.operator", operator);
      await api.createEnterpriseAssignment({
        subject_id: subject,
        agent_id: agent,
        profile_id: assignmentProfile || "default",
        role: assignmentRole,
        assigned_by: operator,
        assignment_reason: reason,
        allowed_surfaces: parseList(assignmentSurfaces),
        workspace_scope: parseList(assignmentWorkspace),
        tool_policy: [],
        memory_scope: [],
      });
      showToast(`Assigned ${agent} to ${subject}`, "success");
      setAssignmentSubject("");
      setAssignmentAgent("");
      setAssignmentReason("");
      setAssignmentWorkspace("");
      load();
    } catch (err) {
      showToast(`Assignment failed: ${err}`, "error");
    } finally {
      setBusyAssignment(null);
    }
  };

  const revokeAssignment = async (assignment: EnterpriseAssignmentSummary) => {
    const operator = operatorId.trim() || "dashboard-operator";
    setBusyAssignment(assignment.assignment_id);
    try {
      await api.revokeEnterpriseAssignment(assignment.assignment_id, {
        revoked_by: operator,
      });
      showToast(`Revoked ${assignment.agent_id}`, "success");
      load();
    } catch (err) {
      showToast(`Revoke failed: ${err}`, "error");
    } finally {
      setBusyAssignment(null);
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
          <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
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
              icon={Users}
              label="Active assignments"
              value={String(snapshot.counts.assignments_active)}
              tone={snapshot.counts.assignments_active > 0 ? "success" : "secondary"}
              badge={snapshot.counts.assignments_active > 0 ? "assigned" : "none"}
            />
            <MetricCard
              icon={Activity}
              label="Audit events"
              value={String(snapshot.counts.audit_total)}
              tone="secondary"
              badge="ledger"
            />
          </div>

          <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(340px,0.9fr)]">
            <ApprovalQueue
              approvals={snapshot.pending_approvals}
              busyStage={busyStage}
              selectedStageId={selectedStage?.stage_id ?? null}
              onSelect={setSelectedStageId}
            />

            <ApprovalInspector
              stage={selectedStage}
              busy={selectedStage ? busyStage === selectedStage.stage_id : false}
              operatorId={operatorId}
              reason={approvalReason}
              ttlMinutes={ttlMinutes}
              onOperatorChange={setOperatorId}
              onReasonChange={setApprovalReason}
              onTtlChange={setTtlMinutes}
              onApprove={approve}
              onDeny={deny}
              onExport={exportEvidence}
            />
          </div>

          <AssignmentControl
            data={assignments}
            busyAssignment={busyAssignment}
            operatorId={operatorId}
            subject={assignmentSubject}
            agent={assignmentAgent}
            profile={assignmentProfile}
            role={assignmentRole}
            reason={assignmentReason}
            surfaces={assignmentSurfaces}
            workspace={assignmentWorkspace}
            onSubjectChange={setAssignmentSubject}
            onAgentChange={setAssignmentAgent}
            onProfileChange={setAssignmentProfile}
            onRoleChange={setAssignmentRole}
            onReasonChange={setAssignmentReason}
            onSurfacesChange={setAssignmentSurfaces}
            onWorkspaceChange={setAssignmentWorkspace}
            onCreate={createAssignment}
            onRevoke={revokeAssignment}
          />

          <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-3">
            <ControlHealth
              checks={snapshot.doctor.checks}
              failedChecks={failedChecks}
              warningChecks={warningChecks}
              counts={snapshot.counts}
            />
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
  selectedStageId,
  onSelect,
}: {
  approvals: EnterpriseApprovalSummary[];
  busyStage: string | null;
  selectedStageId: string | null;
  onSelect: (stageId: string) => void;
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
          const selected = selectedStageId === stage.stage_id;
          return (
            <Card
              key={stage.stage_id}
              className={cn(
                "min-w-0 overflow-hidden transition-colors",
                selected && "border-primary/70 bg-primary/5",
              )}
            >
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
                    outlined={!selected}
                    onClick={() => onSelect(stage.stage_id)}
                    disabled={busy}
                    title="Review"
                    aria-label={`Review ${stage.tool_name}`}
                  >
                    {busy ? <Spinner /> : <Eye className="h-3 w-3" />}
                    Review
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

function ApprovalInspector({
  stage,
  busy,
  operatorId,
  reason,
  ttlMinutes,
  onOperatorChange,
  onReasonChange,
  onTtlChange,
  onApprove,
  onDeny,
  onExport,
}: {
  stage: EnterpriseApprovalSummary | null;
  busy: boolean;
  operatorId: string;
  reason: string;
  ttlMinutes: number;
  onOperatorChange: (value: string) => void;
  onReasonChange: (value: string) => void;
  onTtlChange: (value: number) => void;
  onApprove: (stage: EnterpriseApprovalSummary) => void;
  onDeny: (stage: EnterpriseApprovalSummary) => void;
  onExport: (stage?: EnterpriseApprovalSummary | null) => void;
}) {
  const reasonReady = reason.trim().length > 0;

  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <UserRound className="h-4 w-4" />
        Operator review
      </H2>

      <Card className="min-w-0 overflow-hidden">
        {!stage ? (
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No action selected.
          </CardContent>
        ) : (
          <>
            <CardHeader className="gap-3 px-4 py-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Badge tone={statusTone(stage.risk_tier)}>{stage.risk_tier || "risk"}</Badge>
                <span className="truncate font-medium text-sm">{stage.tool_name}</span>
                <Badge tone="outline">{stage.subject_id}</Badge>
              </div>
              <p className="line-clamp-2 text-xs text-muted-foreground">
                {safeArgsPreview(stage.safe_args)}
              </p>
            </CardHeader>

            <CardContent className="grid gap-4">
              <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_120px]">
                <label className="grid gap-1 text-xs text-muted-foreground">
                  Operator
                  <Input
                    value={operatorId}
                    onChange={(event) => onOperatorChange(event.target.value)}
                    placeholder="manager-id"
                  />
                </label>
                <label className="grid gap-1 text-xs text-muted-foreground">
                  Grant TTL
                  <Input
                    min={1}
                    max={1440}
                    type="number"
                    value={ttlMinutes}
                    onChange={(event) => onTtlChange(Math.max(1, Number(event.target.value) || 1))}
                  />
                </label>
              </div>

              <label className="grid gap-1 text-xs text-muted-foreground">
                Decision reason
                <textarea
                  value={reason}
                  onChange={(event) => onReasonChange(event.target.value)}
                  placeholder="ticket, incident, or business reason"
                  className="min-h-24 w-full resize-y border border-input bg-background px-3 py-2 text-sm text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
                />
              </label>

              <dl className="grid min-w-0 gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                <KeyValue label="Stage" value={shortHash(stage.stage_id)} mono />
                <KeyValue label="Action" value={shortHash(stage.action_hash)} mono />
                <KeyValue label="Idempotency" value={shortHash(stage.idempotency_key)} mono />
                <KeyValue label="Created" value={formatTime(stage.created_at)} />
                <KeyValue label="Effects" value={compactList(stage.requested_side_effects)} />
                <KeyValue label="Detectors" value={compactList(stage.detectors)} />
              </dl>

              <div className="grid gap-2 border-t border-border pt-3">
                <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                  Redacted preview
                </p>
                <div className="grid gap-1">
                  {Object.entries(stage.safe_args).length === 0 ? (
                    <p className="text-xs text-muted-foreground">No preview fields.</p>
                  ) : (
                    Object.entries(stage.safe_args).map(([key, value]) => (
                      <div
                        key={key}
                        className="grid min-w-0 gap-1 border border-border bg-secondary/20 px-3 py-2 text-xs sm:grid-cols-[110px_minmax(0,1fr)]"
                      >
                        <span className="truncate text-muted-foreground">{key}</span>
                        <span className="truncate font-mono-ui text-foreground">
                          {formatSafeValue(value)}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  size="sm"
                  outlined
                  onClick={() => onExport(stage)}
                  title="Export stage evidence"
                  aria-label={`Export evidence for ${stage.tool_name}`}
                >
                  <Download className="h-3 w-3" />
                  Export
                </Button>
                <Button
                  size="sm"
                  onClick={() => onApprove(stage)}
                  disabled={busy || !reasonReady}
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
                  disabled={busy || !reasonReady}
                  title="Deny"
                  aria-label={`Deny ${stage.tool_name}`}
                >
                  <X className="h-3 w-3" />
                  Deny
                </Button>
              </div>
            </CardContent>
          </>
        )}
      </Card>
    </section>
  );
}

function AssignmentControl({
  data,
  busyAssignment,
  operatorId,
  subject,
  agent,
  profile,
  role,
  reason,
  surfaces,
  workspace,
  onSubjectChange,
  onAgentChange,
  onProfileChange,
  onRoleChange,
  onReasonChange,
  onSurfacesChange,
  onWorkspaceChange,
  onCreate,
  onRevoke,
}: {
  data: EnterpriseAssignmentsResponse | null;
  busyAssignment: string | null;
  operatorId: string;
  subject: string;
  agent: string;
  profile: string;
  role: string;
  reason: string;
  surfaces: string;
  workspace: string;
  onSubjectChange: (value: string) => void;
  onAgentChange: (value: string) => void;
  onProfileChange: (value: string) => void;
  onRoleChange: (value: string) => void;
  onReasonChange: (value: string) => void;
  onSurfacesChange: (value: string) => void;
  onWorkspaceChange: (value: string) => void;
  onCreate: () => void;
  onRevoke: (assignment: EnterpriseAssignmentSummary) => void;
}) {
  const assignments = data?.assignments ?? [];
  const profiles = data?.profiles ?? [];
  const control = data?.control;
  const ready = subject.trim() && agent.trim() && reason.trim();

  return (
    <section className="flex min-w-0 flex-col gap-3">
      <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
        <UserPlus className="h-4 w-4" />
        Agent assignments ({assignments.length})
      </H2>

      <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-[minmax(360px,0.9fr)_minmax(0,1.1fr)]">
        <Card className="min-w-0 overflow-hidden">
          <CardHeader className="px-4 py-3">
            <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone="outline">{control?.subject.subject_id ?? "local-admin"}</Badge>
              <span className="text-xs text-muted-foreground">
                {(control?.subject.roles ?? ["admin"]).join(", ")}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-xs text-muted-foreground">
                Employee or team
                <Input
                  value={subject}
                  onChange={(event) => onSubjectChange(event.target.value)}
                  placeholder="employee:jane"
                />
              </label>
              <label className="grid gap-1 text-xs text-muted-foreground">
                Agent identity
                <Input
                  value={agent}
                  onChange={(event) => onAgentChange(event.target.value)}
                  placeholder="repo-coder"
                />
              </label>
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              <label className="grid gap-1 text-xs text-muted-foreground">
                Backing profile
                <select
                  value={profile}
                  onChange={(event) => onProfileChange(event.target.value)}
                  className="h-9 w-full border border-border bg-background/40 px-3 text-sm text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  {(profiles.length ? profiles : [{ name: "default" } as { name: string }]).map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1 text-xs text-muted-foreground">
                Role
                <select
                  value={role}
                  onChange={(event) => onRoleChange(event.target.value)}
                  className="h-9 w-full border border-border bg-background/40 px-3 text-sm text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <option value="employee">employee</option>
                  <option value="manager">manager</option>
                  <option value="operator">operator</option>
                  <option value="auditor">auditor</option>
                </select>
              </label>
              <label className="grid gap-1 text-xs text-muted-foreground">
                Assigned by
                <Input value={operatorId} readOnly />
              </label>
            </div>

            <label className="grid gap-1 text-xs text-muted-foreground">
              Allowed surfaces
              <Input
                value={surfaces}
                onChange={(event) => onSurfacesChange(event.target.value)}
                placeholder="dashboard, cli, tui, gateway"
              />
            </label>

            <label className="grid gap-1 text-xs text-muted-foreground">
              Workspace scope
              <Input
                value={workspace}
                onChange={(event) => onWorkspaceChange(event.target.value)}
                placeholder="repo:billing-api, jira:SEC"
              />
            </label>

            <label className="grid gap-1 text-xs text-muted-foreground">
              Assignment reason
              <textarea
                value={reason}
                onChange={(event) => onReasonChange(event.target.value)}
                placeholder="team, project, ticket, or review reason"
                className="min-h-20 w-full resize-y border border-input bg-background px-3 py-2 text-sm text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
              />
            </label>

            <div className="flex justify-end">
              <Button size="sm" onClick={onCreate} disabled={busyAssignment === "create" || !ready}>
                {busyAssignment === "create" ? <Spinner /> : <UserPlus className="h-3 w-3" />}
                Assign
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="min-w-0 overflow-hidden">
          <CardContent className="p-0">
            {assignments.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No agent assignments.
              </p>
            ) : (
              <div className="divide-y divide-border">
                {assignments.map((assignment) => (
                  <div key={assignment.assignment_id} className="grid gap-3 px-4 py-3">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <Badge tone={statusTone(assignment.status)}>{assignment.status}</Badge>
                      <span className="truncate font-medium text-sm">
                        {assignment.agent_id}
                      </span>
                      <Badge tone="outline">{assignment.profile_id}</Badge>
                      <span className="ml-auto text-xs text-muted-foreground">
                        {formatTime(assignment.created_at)}
                      </span>
                    </div>
                    <dl className="grid min-w-0 gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                      <KeyValue label="Subject" value={assignment.subject_id} />
                      <KeyValue label="Role" value={assignment.role} />
                      <KeyValue label="Surfaces" value={compactList(assignment.allowed_surfaces)} />
                      <KeyValue label="Workspace" value={compactList(assignment.workspace_scope)} />
                    </dl>
                    {assignment.assignment_reason && (
                      <p className="line-clamp-2 text-xs text-muted-foreground">
                        {assignment.assigned_by}: {assignment.assignment_reason}
                      </p>
                    )}
                    {assignment.status === "active" && (
                      <div className="flex justify-end">
                        <Button
                          size="sm"
                          outlined
                          destructive
                          onClick={() => onRevoke(assignment)}
                          disabled={busyAssignment === assignment.assignment_id}
                        >
                          {busyAssignment === assignment.assignment_id ? <Spinner /> : <X className="h-3 w-3" />}
                          Revoke
                        </Button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
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
                  {event.operator_reason && (
                    <p className="line-clamp-2 text-xs text-muted-foreground">
                      {event.operator_id || "operator"}: {event.operator_reason}
                    </p>
                  )}
                  <p className="truncate font-mono-ui text-xs text-muted-foreground">
                    {event.subject_id} | {event.tool_name || "-"} | {shortHash(event.action_id)}
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
