import { useState, useEffect, useCallback } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { ChannelInstanceData, ChannelInstanceInput } from "./hooks/use-channel-instances";
import type { AgentData } from "@/types/agent";
import { slugify } from "@/lib/slug";
import { credentialsSchema, configSchema, wizardConfig, type FieldDef } from "./channel-schemas";
import { ChannelFields } from "./channel-fields";
import { ChannelScopesInfo } from "./channel-scopes-info";
import { wizardAuthSteps, wizardConfigSteps, wizardEditConfigs } from "./channel-wizard-registry";
import { TelegramGroupOverrides } from "./telegram-group-overrides";
import { CHANNEL_TYPES } from "@/constants/channels";
import { channelInstanceSchema, type ChannelInstanceFormData } from "@/schemas/channel.schema";

type WizardStep = "form" | "auth" | "config";

interface ChannelInstanceFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  instance?: ChannelInstanceData | null;
  agents: AgentData[];
  onSubmit: (data: ChannelInstanceInput) => Promise<unknown>;
  onUpdate?: (id: string, data: Partial<ChannelInstanceInput>) => Promise<unknown>;
}

export function ChannelInstanceFormDialog({
  open,
  onOpenChange,
  instance,
  agents,
  onSubmit,
  onUpdate,
}: ChannelInstanceFormDialogProps) {
  const { t } = useTranslation("channels");

  // Non-form state (dynamic maps + wizard flow)
  const [credsValues, setCredsValues] = useState<Record<string, unknown>>({});
  const [configValues, setConfigValues] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [step, setStep] = useState<WizardStep>("form");
  const [createdInstanceId, setCreatedInstanceId] = useState<string | null>(null);
  const [authCompleted, setAuthCompleted] = useState(false);

  const form = useForm<ChannelInstanceFormData>({
    resolver: zodResolver(channelInstanceSchema),
    mode: "onChange",
    defaultValues: {
      name: "",
      displayName: "",
      channelType: "telegram",
      agentId: "",
      enabled: true,
    },
  });

  const channelType = form.watch("channelType");
  const wizard = wizardConfig[channelType];
  const hasWizard = !instance && !!wizard;
  const channelLabel = CHANNEL_TYPES.find((ct) => ct.value === channelType)?.label ?? channelType;

  // Step navigation
  const totalSteps = hasWizard ? 1 + wizard!.steps.length : 1;
  const currentStepNum = step === "form" ? 1 : (wizard?.steps.indexOf(step as "auth" | "config") ?? 0) + 2;

  const getNextWizardStep = useCallback((current: WizardStep): "auth" | "config" | null => {
    if (!wizard) return null;
    if (current === "form") return wizard.steps[0] ?? null;
    const idx = wizard.steps.indexOf(current as "auth" | "config");
    return idx >= 0 ? wizard.steps[idx + 1] ?? null : null;
  }, [wizard]);

  useEffect(() => {
    if (open) {
      form.reset({
        name: instance?.name ?? "",
        displayName: instance?.display_name ?? "",
        channelType: instance?.channel_type ?? "telegram",
        agentId: instance?.agent_id ?? (agents[0]?.id ?? ""),
        enabled: instance?.enabled ?? true,
      });
      setCredsValues({});

      // Merge schema defaults into config so select fields persist their defaults.
      const ct = instance?.channel_type ?? "telegram";
      const schema = configSchema[ct] ?? [];
      const defaults: Record<string, unknown> = {};
      for (const f of schema) {
        if (f.defaultValue !== undefined) defaults[f.key] = f.defaultValue;
      }
      const merged: Record<string, unknown> = { ...defaults, ...(instance?.config ?? {}) };
      // Convert boolean values to strings for select fields that use "true"/"false" options
      const boolSelectKeys = new Set(
        schema.filter((f) => f.type === "select" && f.options?.some((o) => o.value === "true")).map((f) => f.key),
      );
      for (const key of boolSelectKeys) {
        if (typeof merged[key] === "boolean") merged[key] = String(merged[key]);
        else if (merged[key] === undefined || merged[key] === null) merged[key] = "inherit";
      }
      setConfigValues(merged);
      setError("");
      setStep("form");
      setCreatedInstanceId(null);
      setAuthCompleted(false);
    }
  }, [open, instance, agents, form]);

  // Auto-advance from auth to next step on completion
  useEffect(() => {
    if (step !== "auth" || !authCompleted) return;
    const next = getNextWizardStep("auth");
    const id = setTimeout(() => {
      if (next) setStep(next);
      else onOpenChange(false);
    }, 1200);
    return () => clearTimeout(id);
  }, [step, authCompleted, getNextWizardStep, onOpenChange]);

  const handleCredsChange = useCallback((key: string, value: unknown) => {
    setCredsValues((prev) => ({ ...prev, [key]: value }));
  }, []);

  const handleConfigChange = useCallback((key: string, value: unknown) => {
    setConfigValues((prev) => ({ ...prev, [key]: value }));
  }, []);

  // Convert select fields with "true"/"false"/"inherit" values to proper JSON types.
  // "inherit" → remove key (nil on Go side), "true"/"false" → boolean.
  const coerceBoolSelects = (cfg: Record<string, unknown>, schema: FieldDef[]) => {
    const boolSelectKeys = new Set(
      schema.filter((f) => f.type === "select" && f.options?.some((o) => o.value === "true")).map((f) => f.key),
    );
    for (const key of boolSelectKeys) {
      const v = cfg[key];
      if (v === "true") cfg[key] = true;
      else if (v === "false") cfg[key] = false;
      else delete cfg[key]; // "inherit" or unset
    }
  };

  const handleSubmit = form.handleSubmit(async (values) => {
    if (!instance) {
      const schema = credentialsSchema[values.channelType] ?? [];
      const missing = schema.filter((f) => f.required && !credsValues[f.key]);
      if (missing.length > 0) {
        setError(t("form.errors.requiredFields", { fields: missing.map((f) => f.label).join(", ") }));
        return;
      }
    }

    const cleanConfig = Object.fromEntries(
      Object.entries(configValues).filter(([, v]) => v !== undefined && v !== "" && v !== null),
    );
    coerceBoolSelects(cleanConfig, configSchema[values.channelType] ?? []);
    const cleanCreds = Object.fromEntries(
      Object.entries(credsValues).filter(([, v]) => v !== undefined && v !== "" && v !== null),
    );

    setLoading(true);
    setError("");
    try {
      const data: ChannelInstanceInput = {
        name: values.name,
        display_name: values.displayName?.trim() || undefined,
        channel_type: values.channelType,
        agent_id: values.agentId,
        config: Object.keys(cleanConfig).length > 0 ? cleanConfig : undefined,
        enabled: values.enabled,
      };
      if (Object.keys(cleanCreds).length > 0) data.credentials = cleanCreds;

      const result = await onSubmit(data);

      if (hasWizard && wizard) {
        const res = result as Record<string, unknown> | undefined;
        const firstStep = wizard.steps[0];
        if (typeof res?.id === "string" && firstStep) {
          setCreatedInstanceId(res.id);
          setStep(firstStep);
        } else {
          onOpenChange(false);
        }
      } else {
        onOpenChange(false);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("form.errors.failedSave"));
    } finally {
      setLoading(false);
    }
  });

  const handleConfigDone = async () => {
    if (!createdInstanceId || !onUpdate) { onOpenChange(false); return; }
    const cleanConfig = Object.fromEntries(
      Object.entries(configValues).filter(([, v]) => v !== undefined && v !== "" && v !== null),
    );
    coerceBoolSelects(cleanConfig, configSchema[channelType] ?? []);
    setLoading(true);
    setError("");
    try {
      await onUpdate(createdInstanceId, { config: cleanConfig });
      onOpenChange(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("form.errors.failedSaveConfig"));
    } finally {
      setLoading(false);
    }
  };

  const handleSkipAuth = () => {
    const next = getNextWizardStep("auth");
    if (next) setStep(next);
    else onOpenChange(false);
  };

  const canClose = step !== "auth";
  const credsFields = credentialsSchema[channelType] ?? [];
  const excludeSet = new Set(wizard?.excludeConfigFields ?? []);
  const cfgFields = configSchema[channelType] ?? [];
  const formCfgFields = excludeSet.size > 0 ? cfgFields.filter((f) => !excludeSet.has(f.key)) : cfgFields;

  // Lookup registered step components for current channel type
  const AuthStep = wizardAuthSteps[channelType];
  const ConfigStep = wizardConfigSteps[channelType];
  const EditConfig = wizardEditConfigs[channelType];

  const dialogTitle = instance
    ? t("form.editTitle")
    : step === "form"
      ? t("form.createTitle")
      : step === "auth"
        ? t("form.authenticate", { label: channelLabel })
        : t("form.configure", { label: channelLabel });

  const { register, control, formState: { errors } } = form;

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!loading && canClose) onOpenChange(v); }}>
      <DialogContent className="max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{dialogTitle}</DialogTitle>
          {hasWizard && (
            <p className="text-xs text-muted-foreground">
              {t("form.step", { current: currentStepNum, total: totalSteps })}
            </p>
          )}
        </DialogHeader>

        {/* === FORM STEP === */}
        {step === "form" && (
          <>
            <div className="grid gap-4 py-2 -mx-4 px-4 sm:-mx-6 sm:px-6 overflow-y-auto min-h-0">
              <div className="grid gap-1.5">
                <Label htmlFor="ci-name">{t("form.key")}</Label>
                <Input
                  id="ci-name"
                  {...register("name", {
                    setValueAs: (v: string) => slugify(v),
                  })}
                  onChange={(e) => form.setValue("name", slugify(e.target.value), { shouldValidate: true })}
                  value={form.watch("name")}
                  placeholder={t("form.keyPlaceholder")}
                  disabled={!!instance}
                />
                {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                <p className="text-xs text-muted-foreground">{t("form.keyHint")}</p>
              </div>

              <div className="grid gap-1.5">
                <Label htmlFor="ci-display">{t("form.displayName")}</Label>
                <Input
                  id="ci-display"
                  {...register("displayName")}
                  placeholder={t("form.displayNamePlaceholder")}
                />
              </div>

              <div className="grid gap-1.5">
                <Label>{t("form.channelType")}</Label>
                <Controller
                  control={control}
                  name="channelType"
                  render={({ field }) => (
                    <Select value={field.value} onValueChange={field.onChange} disabled={!!instance}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {CHANNEL_TYPES.map((ct) => (
                          <SelectItem key={ct.value} value={ct.value}>{ct.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
              </div>

              <div className="grid gap-1.5">
                <Label>{t("form.agent")}</Label>
                <Controller
                  control={control}
                  name="agentId"
                  render={({ field }) => (
                    <Select value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger><SelectValue placeholder={t("form.selectAgent")} /></SelectTrigger>
                      <SelectContent>
                        {agents.map((a) => (
                          <SelectItem key={a.id} value={a.id}>{a.display_name || a.agent_key}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
                {errors.agentId && <p className="text-xs text-destructive">{errors.agentId.message}</p>}
              </div>

              {credsFields.length > 0 && (
                <fieldset className="rounded-md border p-3 space-y-3">
                  <legend className="px-1 text-sm font-medium">
                    {t("form.credentials")}
                    {instance && <span className="text-xs font-normal text-muted-foreground ml-1">{t("form.credentialsHint")}</span>}
                  </legend>
                  <ChannelFields fields={credsFields} values={credsValues} onChange={handleCredsChange} idPrefix="ci-cred" isEdit={!!instance} contextValues={configValues} />
                  <p className="text-xs text-muted-foreground">{t("form.credentialsEncrypted")}</p>
                </fieldset>
              )}

              <ChannelScopesInfo channelType={channelType} />

              {/* Auth status indicator (edit mode, channels with auth wizard step) */}
              {instance && wizard?.steps.includes("auth") && (
                <div className="rounded-md border border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950 p-3">
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${instance.has_credentials ? "bg-green-500" : "bg-amber-500"}`} />
                    <span className="text-sm">
                      {instance.has_credentials
                        ? t("form.authStatus.authenticated")
                        : t("form.authStatus.notAuthenticated")}
                    </span>
                    {!instance.has_credentials && (
                      <span className="text-xs text-muted-foreground ml-1">{t("form.authStatus.useQrHint")}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Wizard info banner (create mode) */}
              {hasWizard && wizard?.formBanner && (
                <div className="rounded-md border border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950 p-3">
                  <p className="text-sm text-muted-foreground">{t(wizard.formBanner)}</p>
                </div>
              )}

              {formCfgFields.length > 0 && (
                <fieldset className="rounded-md border p-3 space-y-3">
                  <legend className="px-1 text-sm font-medium">{t("form.configuration")}</legend>
                  <ChannelFields fields={formCfgFields} values={configValues} onChange={handleConfigChange} idPrefix="ci-cfg" />
                  {instance && EditConfig && <EditConfig instance={instance} configValues={configValues} onConfigChange={handleConfigChange} />}
                </fieldset>
              )}

              {/* Telegram group/topic overrides */}
              {channelType === "telegram" && (
                <TelegramGroupOverrides
                  groups={(configValues.groups as Record<string, Record<string, unknown>>) ?? {}}
                  onChange={(groups) => {
                    setConfigValues((prev) => ({
                      ...prev,
                      groups: Object.keys(groups).length > 0 ? groups : undefined,
                    }));
                  }}
                />
              )}

              <div className="flex items-center gap-2">
                <Controller
                  control={control}
                  name="enabled"
                  render={({ field }) => (
                    <Switch id="ci-enabled" checked={field.value} onCheckedChange={field.onChange} />
                  )}
                />
                <Label htmlFor="ci-enabled">{t("form.enabled")}</Label>
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>{t("form.cancel")}</Button>
              <Button onClick={handleSubmit} disabled={loading}>
                {loading ? t("form.saving") : instance ? t("form.update") : (wizard?.createLabel ? t(wizard.createLabel) : t("form.create"))}
              </Button>
            </DialogFooter>
          </>
        )}

        {/* === AUTH STEP (rendered by registered component) === */}
        {step === "auth" && createdInstanceId && AuthStep && (
          <AuthStep
            instanceId={createdInstanceId}
            onComplete={() => setAuthCompleted(true)}
            onSkip={handleSkipAuth}
          />
        )}

        {/* === CONFIG STEP (rendered by registered component) === */}
        {step === "config" && createdInstanceId && ConfigStep && (
          <>
            <div className="py-2 -mx-4 px-4 sm:-mx-6 sm:px-6 overflow-y-auto min-h-0">
              <ConfigStep
                instanceId={createdInstanceId}
                authCompleted={authCompleted}
                configValues={configValues}
                onConfigChange={handleConfigChange}
              />
              {error && <p className="text-sm text-destructive mt-2">{error}</p>}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>{t("form.skip")}</Button>
              <Button onClick={handleConfigDone} disabled={loading}>{loading ? t("form.saving") : t("form.done")}</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
