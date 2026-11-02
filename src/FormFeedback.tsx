export type FieldErrors = Record<string, string>;

export function fieldProps(name: string, errors: FieldErrors, hintId?: string) {
  return {
    id: name,
    "aria-invalid": Boolean(errors[name]),
    "aria-describedby": [hintId, errors[name] ? `${name}-error` : undefined].filter(Boolean).join(" ") || undefined,
  };
}

export function focusFirstError(errors: FieldErrors) {
  const first = Object.keys(errors)[0];
  if (!first) return;
  const field = document.getElementById(first);
  let ancestor = field?.parentElement;
  while (ancestor) {
    if (ancestor instanceof HTMLDetailsElement) ancestor.open = true;
    ancestor = ancestor.parentElement;
  }
  field?.focus();
}

export function FieldError({ name, errors }: { name: string; errors: FieldErrors }) {
  return errors[name] ? <span className="field-error" id={`${name}-error`} role="alert">{errors[name]}</span> : null;
}
