// Lightweight label maps (no dependency). Technical terms stay in English;
// user-facing status words are translated to PT-BR.

export const scanStatusLabel: Record<string, string> = {
  PENDING: "Pendente",
  RUNNING: "Em andamento",
  COMPLETED: "Concluído",
  FAILED: "Falhou",
};

export function statusPt(status: string): string {
  return scanStatusLabel[status] ?? status;
}

export function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
