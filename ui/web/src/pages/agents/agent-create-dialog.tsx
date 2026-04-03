import { useMemo, useEffect } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Combobox } from "@/components/ui/combobox";
import type { AgentData } from "@/types/agent";
import { slugify } from "@/lib/slug";
import { useProviders } from "@/pages/providers/hooks/use-providers";
import { useProviderModels } from "@/pages/providers/hooks/use-provider-models";
import { useProviderVerify } from "@/pages/providers/hooks/use-provider-verify";
import { useAgentPresets } from "./agent-presets";
import { agentCreateSchema, type AgentCreateFormData } from "@/schemas/agent.schema";
import { useState } from "react";

interface AgentCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (data: Partial<AgentData>) => Promise<unknown>;
}

export function AgentCreateDialog({ open, onOpenChange, onCreate }: AgentCreateDialogProps) {
  const { t } = useTranslation("agents");
  const agentPresets = useAgentPresets();
  const { providers } = useProviders();
  const [loading, setLoading] = useState(false);
  const [submitError, setSubmitError] = useState("");

  const form = useForm<AgentCreateFormData>({
    resolver: zodResolver(agentCreateSchema),
    mode: "onChange",
    defaultValues: {
      emoji: "",
      displayName: "",
      agentKey: "",
      provider: "",
      model: "",
      agentType: "predefined",
      description: "",
      selfEvolve: false,
    },
  });

  const { register, control, handleSubmit, watch, setValue, reset, formState: { errors } } = form;

  const provider = watch("provider");
  const model = watch("model");
  const agentType = watch("agentType");

  const enabledProviders = providers.filter((p) => p.enabled);

  const selectedProvider = useMemo(
    () => enabledProviders.find((p) => p.name === provider),
    [enabledProviders, provider],
  );
  const selectedProviderId = selectedProvider?.id;
  const { models, loading: modelsLoading } = useProviderModels(selectedProviderId);
  const { verify, verifying, result: verifyResult, reset: resetVerify } = useProviderVerify();

  // Reset verification when provider or model changes
  useEffect(() => {
    resetVerify();
  }, [provider, model, resetVerify]);

  // Reset form when dialog closes
  useEffect(() => {
    if (!open) {
      reset();
      setSubmitError("");
      resetVerify();
    }
  }, [open, reset, resetVerify]);

  const handleVerify = async () => {
    if (!selectedProviderId || !model.trim()) return;
    await verify(selectedProviderId, model.trim());
  };

  const handleVerifyAndCreate = async () => {
    if (!selectedProviderId || !model.trim()) return;
    const res = await verify(selectedProviderId, model.trim());
    if (res?.valid) await handleSubmitForm(form.getValues());
  };

  const handleSubmitForm = async (data: AgentCreateFormData) => {
    setLoading(true);
    setSubmitError("");
    try {
      const otherConfig: Record<string, unknown> = {};
      if (data.emoji?.trim()) otherConfig.emoji = data.emoji.trim();
      if (data.description?.trim()) otherConfig.description = data.description.trim();
      if (data.selfEvolve) otherConfig.self_evolve = true;
      await onCreate({
        agent_key: data.agentKey,
        display_name: data.displayName || undefined,
        provider: data.provider,
        model: data.model,
        agent_type: data.agentType,
        other_config: Object.keys(otherConfig).length > 0 ? otherConfig : undefined,
      });
      onOpenChange(false);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : t("create.failedToCreate"));
    } finally {
      setLoading(false);
    }
  };

  const handleProviderChange = (value: string) => {
    setValue("provider", value, { shouldValidate: true });
    setValue("model", "", { shouldValidate: false });
  };

  const displayName = watch("displayName");
  const agentKey = watch("agentKey");

  // Derived submit button state
  const canCreate = !!agentKey && !!displayName && !!provider && !!model &&
    !errors.agentKey && !errors.displayName &&
    (agentType !== "predefined" || !!watch("description")?.trim());

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-4xl max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{t("create.title")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-4 -mx-4 px-4 sm:-mx-6 sm:px-6 overflow-y-auto min-h-0">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="displayName">{t("create.displayName")}</Label>
              <div className="flex gap-2">
                <Input
                  id="emoji"
                  {...register("emoji")}
                  placeholder="🤖"
                  className="w-14 shrink-0 text-center text-lg"
                  maxLength={2}
                  title={t("create.emojiHint")}
                />
                <Input
                  id="displayName"
                  {...register("displayName")}
                  onBlur={(e) => {
                    register("displayName").onBlur(e);
                    const name = e.target.value.trim();
                    if (name && !form.getFieldState("agentKey").isDirty) {
                      setValue("agentKey", slugify(name), { shouldValidate: true });
                    }
                  }}
                  placeholder={t("create.displayNamePlaceholder")}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="agentKey">{t("create.agentKey")}</Label>
              <Input
                id="agentKey"
                {...register("agentKey")}
                onBlur={(e) => {
                  setValue("agentKey", slugify(e.target.value), { shouldValidate: true });
                }}
                placeholder={t("create.agentKeyPlaceholder")}
              />
              {errors.agentKey ? (
                <p className="text-xs text-destructive">{errors.agentKey.message}</p>
              ) : (
                <p className="text-xs text-muted-foreground">{t("create.agentKeyHint")}</p>
              )}
            </div>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("create.provider")}</Label>
              {enabledProviders.length > 0 ? (
                <Controller
                  control={control}
                  name="provider"
                  render={({ field }) => (
                    <Select value={field.value} onValueChange={handleProviderChange}>
                      <SelectTrigger>
                        <SelectValue placeholder={t("create.selectProvider")} />
                      </SelectTrigger>
                      <SelectContent>
                        {enabledProviders.map((p) => (
                          <SelectItem key={p.name} value={p.name}>
                            {p.display_name || p.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
              ) : (
                <Input
                  {...register("provider")}
                  placeholder="openrouter"
                />
              )}
            </div>
            <div className="space-y-2">
              <Label>{t("create.model")}</Label>
              <div className="flex gap-2">
                <div className="flex-1">
                  <Controller
                    control={control}
                    name="model"
                    render={({ field }) => (
                      <Combobox
                        value={field.value}
                        onChange={(v) => setValue("model", v, { shouldValidate: true })}
                        options={models.map((m) => ({ value: m.id, label: m.name }))}
                        placeholder={modelsLoading ? t("create.loadingModels") : t("create.enterOrSelectModel")}
                      />
                    )}
                  />
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-9 px-3"
                  disabled={!selectedProviderId || !model.trim() || verifying}
                  onClick={handleVerify}
                >
                  {verifying ? "..." : t("create.check")}
                </Button>
              </div>
              {verifyResult && (
                <p className={`text-xs ${verifyResult.valid ? "text-success" : "text-destructive"}`}>
                  {verifyResult.valid ? t("create.modelVerified") : verifyResult.error || t("create.verificationFailed")}
                </p>
              )}
              {!verifyResult && provider && !modelsLoading && models.length === 0 && (
                <p className="text-xs text-muted-foreground">{t("create.noModelsHint")}</p>
              )}
            </div>
          </div>
          {agentType === "predefined" ? (
            <div className="space-y-3">
              <Label>{t("create.describeAgent")}</Label>
              <div className="flex flex-wrap gap-1.5">
                {agentPresets.map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => setValue("description", preset.prompt, { shouldValidate: true })}
                    className="rounded-full border px-2.5 py-0.5 text-xs transition-colors hover:bg-accent"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <Textarea
                {...register("description")}
                placeholder={t("create.descriptionPlaceholder")}
                className="min-h-[120px]"
              />
              <p className="text-xs text-muted-foreground">
                {t("create.descriptionHint")}
              </p>
              <div className="flex items-center justify-between gap-4 rounded-md border px-3 py-2.5">
                <div className="space-y-0.5">
                  <Label htmlFor="create-self-evolve" className="text-sm font-normal">{t("create.selfEvolution")}</Label>
                  <p className="text-xs text-muted-foreground">{t("create.selfEvolutionHint")}</p>
                </div>
                <Controller
                  control={control}
                  name="selfEvolve"
                  render={({ field }) => (
                    <Switch id="create-self-evolve" checked={field.value} onCheckedChange={field.onChange} />
                  )}
                />
              </div>
            </div>
          ) : (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2.5 space-y-2">
              <p className="text-xs text-amber-700 dark:text-amber-400">
                {t("create.openWarning")}
              </p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                onClick={() => setValue("agentType", "predefined")}
              >
                {t("create.switchToPredefined")}
              </Button>
            </div>
          )}

          {/* Collapsible toggle for Open agent type */}
          <button
            type="button"
            onClick={() => setValue("agentType", agentType === "open" ? "predefined" : "open")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ChevronRight className={`h-3 w-3 transition-transform ${agentType === "open" ? "rotate-90" : ""}`} />
            {t("create.useOpenAgent")}
          </button>

          {submitError && (
            <p className="text-sm text-destructive">{submitError}</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
            {t("create.cancel")}
          </Button>
          {loading ? (
            <Button disabled>{t("create.creating")}</Button>
          ) : !verifyResult?.valid && selectedProviderId && model.trim() ? (
            <Button
              onClick={handleVerifyAndCreate}
              disabled={verifying || !canCreate}
            >
              {verifying ? t("create.checking") : t("create.checkAndCreate")}
            </Button>
          ) : (
            <Button
              onClick={handleSubmit(handleSubmitForm)}
              disabled={!canCreate || !verifyResult?.valid || loading}
            >
              {t("create.create")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
