import { useState, useEffect, useCallback, useMemo } from "react";
import { Play, Loader2, Heart, Clock, FileText, Cpu } from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useMinLoading } from "@/hooks/use-min-loading";
import { useChannels } from "@/pages/channels/hooks/use-channels";
import { useProviders } from "@/pages/providers/hooks/use-providers";
import { useUiStore } from "@/stores/use-ui-store";
import { ProviderModelSelect } from "@/components/shared/provider-model-select";
import { isValidIanaTimezone } from "@/lib/constants";
import { toast } from "@/stores/use-toast-store";
import type { HeartbeatConfig, DeliveryTarget } from "@/pages/agents/hooks/use-agent-heartbeat";
import { HeartbeatScheduleSection } from "./heartbeat-schedule-section";
import { HeartbeatAdvancedPanel } from "./heartbeat-advanced-panel";
import { HeartbeatDeliverySection } from "./heartbeat-delivery-section";

interface HeartbeatConfigDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: HeartbeatConfig | null;
  saving: boolean;
  update: (params: Partial<HeartbeatConfig> & { providerName?: string }) => Promise<void>;
  test: () => Promise<void>;
  getChecklist: () => Promise<string>;
  setChecklist: (content: string) => Promise<void>;
  fetchTargets: () => Promise<DeliveryTarget[]>;
  refresh: () => Promise<void>;
  agentProvider?: string;
  agentModel?: string;
}

export function HeartbeatConfigDialog({
  open, onOpenChange, config, saving, update, test, getChecklist, setChecklist, fetchTargets, refresh,
  agentProvider, agentModel,
}: HeartbeatConfigDialogProps) {
  const { t } = useTranslation("agents");
  const { channels: availableChannels } = useChannels();
  const { providers } = useProviders();
  const channelNames = Object.keys(availableChannels);
  const userTz = useUiStore((s) => s.timezone);
  const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const defaultTz = userTz && userTz !== "auto" ? userTz : browserTz;

  const [enabled, setEnabled] = useState(false);
  const [intervalMin, setIntervalMin] = useState(30);
  const [ackMaxChars, setAckMaxChars] = useState(300);
  const [maxRetries, setMaxRetries] = useState(2);
  const [isolatedSession, setIsolatedSession] = useState(false);
  const [lightContext, setLightContext] = useState(false);
  const [activeHoursStart, setActiveHoursStart] = useState("");
  const [activeHoursEnd, setActiveHoursEnd] = useState("");
  const [timezone, setTimezone] = useState("");
  const [channel, setChannel] = useState("");
  const [chatId, setChatId] = useState("");
  const [hbProvider, setHbProvider] = useState("");
  const [hbModel, setHbModel] = useState("");
  const [checklist, setChecklistState] = useState("");
  const [originalChecklist, setOriginalChecklist] = useState("");
  const [checklistLoading, setChecklistLoading] = useState(false);
  const [targets, setTargets] = useState<DeliveryTarget[]>([]);
  const [testRunning, setTestRunning] = useState(false);
  const showTestSpin = useMinLoading(testRunning, 600);

  const providerNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const p of providers) map[p.id] = p.name;
    return map;
  }, [providers]);

  const loadChecklist = useCallback(async () => {
    setChecklistLoading(true);
    try {
      const content = await getChecklist();
      setChecklistState(content);
      setOriginalChecklist(content);
    } catch { /* ignore */ } finally {
      setChecklistLoading(false);
    }
  }, [getChecklist]);

  useEffect(() => {
    if (!open) return;
    if (config) {
      setEnabled(config.enabled);
      setIntervalMin(Math.round(config.intervalSec / 60));
      setAckMaxChars(config.ackMaxChars);
      setMaxRetries(config.maxRetries);
      setIsolatedSession(config.isolatedSession);
      setLightContext(config.lightContext);
      setActiveHoursStart(config.activeHoursStart ?? "");
      setActiveHoursEnd(config.activeHoursEnd ?? "");
      setTimezone(config.timezone || defaultTz);
      setChannel(config.channel ?? "");
      setChatId(config.chatId ?? "");
      setHbProvider(config.providerId ? (providerNameById[config.providerId] ?? "") : "");
      setHbModel(config.model ?? "");
    } else {
      setTimezone(defaultTz);
      setHbProvider("");
      setHbModel("");
    }
    loadChecklist();
    fetchTargets().then(setTargets).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const handleTest = async () => {
    setTestRunning(true);
    try { await test(); } finally { setTestRunning(false); }
  };

  const handleSave = async () => {
    if (timezone && !isValidIanaTimezone(timezone)) {
      toast.error(t("heartbeat.invalidTimezone", "Invalid timezone"));
      return;
    }
    try {
      const clampedMin = Math.max(5, intervalMin);
      await update({
        enabled,
        intervalSec: clampedMin * 60,
        ackMaxChars,
        maxRetries,
        isolatedSession,
        lightContext,
        activeHoursStart: activeHoursStart || undefined,
        activeHoursEnd: activeHoursEnd || undefined,
        timezone: timezone || undefined,
        channel: channel || undefined,
        chatId: chatId || undefined,
        model: hbModel || undefined,
        providerName: hbProvider || undefined,
      });
      if (checklist !== originalChecklist) {
        await setChecklist(checklist);
        setOriginalChecklist(checklist);
      }
      await refresh();
      onOpenChange(false);
    } catch {
      // toast shown by hook — keep dialog open
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[95vw] flex flex-col sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Heart className="h-4 w-4 text-rose-500" />
            {t("heartbeat.configTitle")}
            <Badge variant={enabled ? "success" : "secondary"} className="text-[10px]">
              {enabled ? t("heartbeat.on") : t("heartbeat.off")}
            </Badge>
          </DialogTitle>
        </DialogHeader>

        <div className="overflow-y-auto min-h-0 -mx-4 px-4 sm:-mx-6 sm:px-6 space-y-4 overscroll-contain">

          {/* Enable + Interval */}
          <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
            <div className="flex items-center gap-3 min-w-0">
              <Switch checked={enabled} onCheckedChange={setEnabled} />
              <div className="min-w-0">
                <span className="text-sm font-medium">{t("heartbeat.enabled")}</span>
                <p className="text-xs text-muted-foreground">{t("heartbeat.enabledHint")}</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <Clock className="h-3.5 w-3.5 text-muted-foreground" />
              <Input
                type="number"
                min={5}
                value={intervalMin}
                onChange={(e) => setIntervalMin(Math.max(5, Number(e.target.value) || 5))}
                className="w-[4.5rem] text-center text-base md:text-sm"
              />
              <span className="text-xs text-muted-foreground">min</span>
            </div>
          </div>

          {/* Provider / Model override */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Cpu className="h-3.5 w-3.5 text-orange-500" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("heartbeat.sectionModel")}
              </h4>
            </div>
            <p className="text-xs text-muted-foreground">{t("heartbeat.modelHint")}</p>
            <ProviderModelSelect
              provider={hbProvider}
              onProviderChange={setHbProvider}
              model={hbModel}
              onModelChange={setHbModel}
              allowEmpty
              showVerify={!!(hbProvider && hbModel)}
              providerPlaceholder={agentProvider ? `(${agentProvider})` : "(agent default)"}
              modelPlaceholder={agentModel ? `(${agentModel})` : "(agent default)"}
            />
          </div>

          <HeartbeatDeliverySection
            channelNames={channelNames}
            channel={channel} setChannel={setChannel}
            chatId={chatId} setChatId={setChatId}
            targets={targets}
          />

          <HeartbeatScheduleSection
            activeHoursStart={activeHoursStart} setActiveHoursStart={setActiveHoursStart}
            activeHoursEnd={activeHoursEnd} setActiveHoursEnd={setActiveHoursEnd}
            timezone={timezone} setTimezone={setTimezone}
            defaultTz={defaultTz}
          />

          <HeartbeatAdvancedPanel
            ackMaxChars={ackMaxChars} setAckMaxChars={setAckMaxChars}
            maxRetries={maxRetries} setMaxRetries={setMaxRetries}
            isolatedSession={isolatedSession} setIsolatedSession={setIsolatedSession}
            lightContext={lightContext} setLightContext={setLightContext}
          />

          {/* Checklist */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <FileText className="h-3.5 w-3.5 text-emerald-500" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("heartbeat.checklist")}
              </h4>
            </div>
            <p className="text-xs text-muted-foreground">{t("heartbeat.checklistHint")}</p>
            {checklistLoading ? (
              <div className="flex items-center gap-2 text-xs text-muted-foreground py-4 justify-center">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {t("heartbeat.checklistLoading")}
              </div>
            ) : (
              <Textarea
                value={checklist}
                onChange={(e) => setChecklistState(e.target.value)}
                placeholder={t("heartbeat.checklistPlaceholder")}
                rows={8}
                className="text-base md:text-sm font-mono resize-y min-h-[120px] sm:min-h-[200px]"
              />
            )}
          </div>

          <div className="h-1" />
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between gap-2 border-t pt-3">
          <Button
            variant="outline" size="sm"
            onClick={handleTest}
            disabled={showTestSpin || saving}
            className="gap-1.5"
          >
            {showTestSpin ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            {t("heartbeat.testRun")}
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
              {t("heartbeat.cancel")}
            </Button>
            <Button size="sm" onClick={handleSave} disabled={saving}>
              {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              {saving ? t("heartbeat.saving") : t("heartbeat.save")}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
