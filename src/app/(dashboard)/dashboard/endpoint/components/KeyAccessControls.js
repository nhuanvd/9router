"use client";

// Per-API-key access control on the Endpoint page.
// "Restrict access" toggle per key; when on, the key may call only the listed
// combos/models and models matching a regex, shown as removable badges.
import { useState } from "react";
import PropTypes from "prop-types";
import { Toggle, ModelSelectModal } from "@/shared/components";

const NO_PATTERNS = [];

export default function KeyAccessControls({ apiKey, onChange, onRequestRestrict }) {
  const access = apiKey.access || { restricted: false, allow: [] };
  const patterns = access.modelPatterns || NO_PATTERNS;
  const [pickerOpen, setPickerOpen] = useState(false);
  const [activeProviders, setActiveProviders] = useState([]);
  const [modelAliases, setModelAliases] = useState({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const openPicker = async () => {
    setPickerOpen(true);
    // Same sources the combo editor feeds the picker with.
    try {
      const [providersRes, aliasRes] = await Promise.all([fetch("/api/providers"), fetch("/api/models/alias")]);
      if (providersRes.ok) setActiveProviders((await providersRes.json()).connections || []);
      if (aliasRes.ok) setModelAliases((await aliasRes.json()).aliases || {});
    } catch (error) {
      console.log("Error loading picker data:", error);
    }
  };

  const save = async (changes) => {
    if (saving) return;
    setSaving(true);
    setError("");
    try {
      const message = await onChange({ ...access, ...changes });
      if (message) setError(message);
    } finally {
      setSaving(false);
    }
  };
  const add = (models) => save({ allow: [...access.allow, ...models.map((model) => model.value)] });
  const remove = (models) => {
    const values = new Set(models.map((model) => model.value.toLowerCase()));
    return save({ allow: access.allow.filter((entry) => !values.has(entry.toLowerCase())) });
  };
  const addPattern = (pattern) => save({ modelPatterns: [...patterns, pattern] });
  const removePattern = (pattern) => save({ modelPatterns: patterns.filter((entry) => entry !== pattern) });
  return (
    <div className="mt-2" data-testid="key-access">
      <Toggle
        size="sm"
        checked={access.restricted}
        disabled={saving}
        label="Restrict access"
        onChange={(checked) => (checked ? onRequestRestrict() : save({ restricted: false }))}
      />
      {access.restricted && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {access.allow.length === 0 && patterns.length === 0 && (
            <span className="text-xs text-orange-500">No combos or models allowed — this key can call nothing.</span>
          )}
          {[...access.allow.map((value) => ({ value, regex: false })), ...patterns.map((value) => ({ value, regex: true }))].map(({ value, regex }) => (
            <span key={`${regex}:${value}`} className="flex items-center gap-1 break-all rounded-xl border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-xs text-text-main">
              {value}
              <button
                type="button"
                disabled={saving}
                onClick={() => regex
                  ? removePattern(value)
                  : remove([{ value }])}
                className="rounded text-text-muted hover:text-red-500"
                title={`Remove ${regex ? "regex " : ""}${value}`}
                aria-label={`Remove ${regex ? "regex " : ""}${value}`}
              >
                <span className="material-symbols-outlined leading-none" style={{ fontSize: "12px" }}>close</span>
              </button>
            </span>
          ))}
          <button
            type="button"
            disabled={saving}
            onClick={openPicker}
            className="flex items-center gap-0.5 rounded-xl border border-dashed border-black/10 px-2 py-0.5 text-xs font-medium text-primary hover:border-primary/50 dark:border-white/10"
          >
            <span className="material-symbols-outlined leading-none" style={{ fontSize: "14px" }}>add</span>
            Add combo or model
          </button>
        </div>
      )}
      {!pickerOpen && error && <p role="alert" className="mt-1 text-xs text-red-500">{error}</p>}
      {pickerOpen && (
        <ModelSelectModal
          isOpen={pickerOpen}
          onClose={() => {
            setPickerOpen(false);
            setError("");
          }}
          onSelect={(model) => add([model])}
          onDeselect={(model) => remove([model])}
          onSelectBatch={add}
          onDeselectBatch={remove}
          activeProviders={activeProviders}
          modelAliases={modelAliases}
          title={`Allowed for "${apiKey.name}"`}
          addedModelValues={access.allow}
          closeOnSelect={false}
          showSectionSelectAll
          modelPatterns={patterns}
          onAddModelPattern={addPattern}
          onRemoveModelPattern={removePattern}
          selectionSaving={saving}
          selectionError={error}
        />
      )}
    </div>
  );
}

KeyAccessControls.propTypes = {
  apiKey: PropTypes.shape({
    id: PropTypes.string.isRequired,
    name: PropTypes.string,
    access: PropTypes.shape({
      restricted: PropTypes.bool,
      allow: PropTypes.arrayOf(PropTypes.string),
      modelPatterns: PropTypes.arrayOf(PropTypes.string),
    }),
  }).isRequired,
  onChange: PropTypes.func.isRequired,
  onRequestRestrict: PropTypes.func.isRequired,
};
