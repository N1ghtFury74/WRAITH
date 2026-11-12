import { AlertTriangle, Loader2, Trash2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { errorText } from "@/lib/reasons";

interface Props {
  /** The case to delete; the dialog is open while this is non-null. */
  caseId: string | null;
  onClose: () => void;
  /** Called after a successful delete (caller clears local state + routes). */
  onDeleted: (caseId: string) => void;
}

/**
 * Type-to-confirm delete dialog (IRREVERSIBLE — removes the case's artifacts +
 * results). The Delete button stays disabled until the operator re-types the case
 * id, and typed server errors (409 run_in_progress, etc.) surface inline.
 */
export function DeleteCaseDialog({ caseId, onClose, onDeleted }: Props) {
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setConfirm("");
    setBusy(false);
    setError(null);
  }

  async function doDelete() {
    if (!caseId) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteCase(caseId);
      reset();
      onDeleted(caseId);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={caseId !== null}
      onOpenChange={(open) => {
        if (!open && !busy) {
          reset();
          onClose();
        }
      }}
    >
      {caseId !== null ? (
        <DialogContent>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="size-4 text-unavailable" /> Delete case
          </DialogTitle>
          <DialogDescription>
            This permanently removes <span className="font-mono text-foreground">{caseId}</span> and all
            of its uploaded artifacts and analysis results. This cannot be undone.
          </DialogDescription>

          <div className="mt-4 space-y-1">
            <label htmlFor="confirm-case-id" className="text-caption text-muted-foreground">
              Type <span className="font-mono text-foreground">{caseId}</span> to confirm
            </label>
            <Input
              id="confirm-case-id"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder={caseId}
              className="font-mono"
              autoComplete="off"
              autoFocus
            />
          </div>

          {error ? <p className="mt-2 text-caption text-unavailable">{error}</p> : null}

          <div className="mt-4 flex justify-end gap-2">
            <DialogClose asChild>
              <Button size="sm" variant="secondary" disabled={busy}>
                Cancel
              </Button>
            </DialogClose>
            <Button size="sm" variant="destructive" disabled={busy || confirm !== caseId} onClick={() => void doDelete()}>
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
              Delete case
            </Button>
          </div>
        </DialogContent>
      ) : null}
    </Dialog>
  );
}
