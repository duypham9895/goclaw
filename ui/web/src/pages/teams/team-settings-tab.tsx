import { useState, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Save, Loader2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CHANNEL_TYPES } from "@/constants/channels";
import type { TeamData, TeamAccessSettings, TeamNotifyConfig, EscalationMode, EscalationAction } from "@/types/team";
import { useTeams } from "./hooks/use-teams";
import { TeamNotificationsSection } from "./team-notifications-section";
import { TeamAccessControlSection } from "./team-access-control-section";
import { TeamOrchestrationSection } from "./team-orchestration-section";

interface TeamSettingsTabProps {
  teamId: string;
  team: TeamData;
  onSaved: () => void;
}

export function TeamSettingsTab({ teamId, team, onSaved }: TeamSettingsTabProps) {
  const { t } = useTranslation("teams");
  const { updateTeamSettings } = useTeams();

  const initial = (team.settings ?? {}) as TeamAccessSettings;
  const [allowUserIds, setAllowUserIds] = useState<string[]>(initial.allow_user_ids ?? []);
  const [denyUserIds, setDenyUserIds] = useState<string[]>(initial.deny_user_ids ?? []);
  const [allowChannels, setAllowChannels] = useState<string[]>(initial.allow_channels ?? []);
  const [denyChannels, setDenyChannels] = useState<string[]>(initial.deny_channels ?? []);
  const initNotify = initial.notifications ?? {};
  const [notifyDispatched, setNotifyDispatched] = useState(initNotify.dispatched ?? true);
  const [notifyProgress, setNotifyProgress] = useState(initNotify.progress ?? false);
  const [notifyFailed, setNotifyFailed] = useState(initNotify.failed ?? false);
  const [notifyCompleted, setNotifyCompleted] = useState(initNotify.completed ?? true);
  const [notifyCommented, setNotifyCommented] = useState(initNotify.commented ?? false);
  const [notifyNewTask, setNotifyNewTask] = useState(initNotify.new_task ?? true);
  const [notifySlowTool, setNotifySlowTool] = useState(initNotify.slow_tool ?? false);
  const [notifyMode, setNotifyMode] = useState<"direct" | "leader">(initNotify.mode ?? "direct");
  const initMemberRequests = initial.member_requests ?? {};
  const [memberRequestsEnabled, setMemberRequestsEnabled] = useState(initMemberRequests.enabled ?? false);
  const [memberRequestsAutoDispatch, setMemberRequestsAutoDispatch] = useState(initMemberRequests.auto_dispatch ?? false);
  const [escalationMode, setEscalationMode] = useState<EscalationMode | "">(initial.escalation_mode ?? "");
  const [escalationActions, setEscalationActions] = useState<EscalationAction[]>(initial.escalation_actions ?? []);
  const initBlockerEscalation = initial.blocker_escalation ?? {};
  const [blockerEscalationEnabled, setBlockerEscalationEnabled] = useState(initBlockerEscalation.enabled ?? true);
  const [followupInterval, setFollowupInterval] = useState<number>(initial.followup_interval_minutes ?? 30);
  const [followupMaxReminders, setFollowupMaxReminders] = useState<number>(initial.followup_max_reminders ?? 0);
  const [workspaceScope, setWorkspaceScope] = useState<string>(initial.workspace_scope ?? "isolated");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const s = (team.settings ?? {}) as TeamAccessSettings;
    setAllowUserIds(s.allow_user_ids ?? []);
    setDenyUserIds(s.deny_user_ids ?? []);
    setAllowChannels(s.allow_channels ?? []);
    setDenyChannels(s.deny_channels ?? []);
    const sn = s.notifications ?? {};
    setNotifyDispatched(sn.dispatched ?? true);
    setNotifyProgress(sn.progress ?? false);
    setNotifyFailed(sn.failed ?? false);
    setNotifyCompleted(sn.completed ?? true);
    setNotifyCommented(sn.commented ?? false);
    setNotifyNewTask(sn.new_task ?? true);
    setNotifySlowTool(sn.slow_tool ?? false);
    setNotifyMode(sn.mode ?? "direct");
    const smr = s.member_requests ?? {};
    setMemberRequestsEnabled(smr.enabled ?? false);
    setMemberRequestsAutoDispatch(smr.auto_dispatch ?? false);
    setEscalationMode(s.escalation_mode ?? "");
    setEscalationActions(s.escalation_actions ?? []);
    const sbe = s.blocker_escalation ?? {};
    setBlockerEscalationEnabled(sbe.enabled ?? true);
    setFollowupInterval(s.followup_interval_minutes ?? 30);
    setFollowupMaxReminders(s.followup_max_reminders ?? 0);
    setWorkspaceScope(s.workspace_scope ?? "isolated");
  }, [team]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      const settings: TeamAccessSettings = {};
      if (allowUserIds.length > 0) settings.allow_user_ids = allowUserIds;
      if (denyUserIds.length > 0) settings.deny_user_ids = denyUserIds;
      if (allowChannels.length > 0) settings.allow_channels = allowChannels;
      if (denyChannels.length > 0) settings.deny_channels = denyChannels;
      const notifications: TeamNotifyConfig = {
        dispatched: notifyDispatched,
        progress: notifyProgress,
        failed: notifyFailed,
        slow_tool: notifySlowTool,
        mode: notifyMode,
        completed: notifyCompleted,
        commented: notifyCommented,
        new_task: notifyNewTask,
      };
      settings.notifications = notifications;
      if (memberRequestsEnabled) {
        settings.member_requests = { enabled: true, auto_dispatch: memberRequestsAutoDispatch };
      }
      if (escalationMode) {
        settings.escalation_mode = escalationMode;
        if (escalationActions.length > 0) settings.escalation_actions = escalationActions;
      }
      settings.blocker_escalation = { enabled: blockerEscalationEnabled };
      if (followupInterval !== 30) settings.followup_interval_minutes = followupInterval;
      if (followupMaxReminders !== 0) settings.followup_max_reminders = followupMaxReminders;
      settings.workspace_scope = workspaceScope || "isolated";
      await updateTeamSettings(teamId, settings);
      onSaved();
    } catch { // toast shown by hook
    } finally {
      setSaving(false);
    }
  }, [teamId, allowUserIds, denyUserIds, allowChannels, denyChannels, notifyDispatched, notifyProgress, notifyFailed, notifyCompleted, notifyCommented, notifyNewTask, notifySlowTool, notifyMode, memberRequestsEnabled, memberRequestsAutoDispatch, escalationMode, escalationActions, blockerEscalationEnabled, followupInterval, followupMaxReminders, workspaceScope, updateTeamSettings, onSaved]);

  const channelOptions = CHANNEL_TYPES.map((c) => ({ value: c.value, label: c.label }));

  return (
    <div className="space-y-6">
      <TeamNotificationsSection
        notifyDispatched={notifyDispatched} setNotifyDispatched={setNotifyDispatched}
        notifyProgress={notifyProgress} setNotifyProgress={setNotifyProgress}
        notifyFailed={notifyFailed} setNotifyFailed={setNotifyFailed}
        notifyCompleted={notifyCompleted} setNotifyCompleted={setNotifyCompleted}
        notifyCommented={notifyCommented} setNotifyCommented={setNotifyCommented}
        notifyNewTask={notifyNewTask} setNotifyNewTask={setNotifyNewTask}
        notifySlowTool={notifySlowTool} setNotifySlowTool={setNotifySlowTool}
        notifyMode={notifyMode} setNotifyMode={setNotifyMode}
      />

      <TeamOrchestrationSection
        workspaceScope={workspaceScope} setWorkspaceScope={setWorkspaceScope}
        memberRequestsEnabled={memberRequestsEnabled} setMemberRequestsEnabled={setMemberRequestsEnabled}
        memberRequestsAutoDispatch={memberRequestsAutoDispatch} setMemberRequestsAutoDispatch={setMemberRequestsAutoDispatch}
        blockerEscalationEnabled={blockerEscalationEnabled} setBlockerEscalationEnabled={setBlockerEscalationEnabled}
        followupInterval={followupInterval} setFollowupInterval={setFollowupInterval}
        followupMaxReminders={followupMaxReminders} setFollowupMaxReminders={setFollowupMaxReminders}
      />

      <TeamAccessControlSection
        allowUserIds={allowUserIds} setAllowUserIds={setAllowUserIds}
        denyUserIds={denyUserIds} setDenyUserIds={setDenyUserIds}
        allowChannels={allowChannels} setAllowChannels={setAllowChannels}
        denyChannels={denyChannels} setDenyChannels={setDenyChannels}
        channelOptions={channelOptions}
      />

      {/* Save button */}
      <div className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? t("settings.saving") : t("settings.save")}
        </Button>
      </div>
    </div>
  );
}
